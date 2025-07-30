import requests
import json
import re
import smtplib
import datetime
import pandas
import io
from devopsdriver import Settings
from difflib import SequenceMatcher
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from email.message import EmailMessage
from email.mime.text import MIMEText

settings = Settings(__file__)

class User():
    def __init__(self, machines=None, name=None, email=None, loc=None):
        self._machines = [m for m in machines] if machines else []
        self._name = name.upper() if name else name
        self._email = email.upper() if email else email
        self._loc = loc.upper() if loc else loc

    def __str__(self):
        return f"{self._name} | Email: {self._email}, Room: {self._loc}"
    
    @property
    def machines(self):
        return self._machines
    @machines.setter
    def machines(self, m):
        if type(m) == list:
            self._machines += m
        else:
            self._machines.append(m)

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, n):
        self._name = n.upper() if n else n

    @property
    def email(self):
        return self._email
    @email.setter
    def email(self, e):
        self._email = e.upper() if e else e

    @property
    def loc(self):
        return self._loc
    @loc.setter
    def loc(self, l):
        self._loc = l.upper() if l else l
    
    def format_email(self):
        if self.machines:
            if self.name == settings["CATCHALL_USER"]:
                content = f"Hi HelpDesk!\nThe following assets have no assigned user/location and need to be updated\n" + f"\n".join([f"{machine.name}: {machine.vulns}" for machine in self.machines])
            else:
                content = """
Dear {0},

We've emailed you to let you know that our Law School security systems have noticed a few areas on your device(s) that could use some updates or adjustments to stay secure.

Please schedule a time with us for this next week to run necessary updates. These updates normally take only 10-15 minutes, and we can come by to run them (e.g., for your desktop tower or laptop) or you can bring your computer to the Help Desk (e.g., for your laptop).

Thank you for helping us keep you and BYU Law School's systems safe!

Best regards,
The Help Desk Team
(801) 422-3884
""".format(self.name.split()[0].title())
            return content
        return False

class Machine():
    def __init__(
            self,
            serial_num=None,
            tag=None,
            loc=None,
            alias=None,
            name=None,
            falcon_count=None,
            user=None,
            vulns=None,
            type=None
        ):
        self._serial = serial_num.upper() if serial_num else serial_num
        self._tag = tag.upper() if tag else tag
        self._loc = loc.upper() if loc else loc
        self._alias = alias.upper() if alias else alias
        self._name = name.upper() if name else name
        self._count = falcon_count if falcon_count else 0
        self._user = user.upper() if user else user
        self._vulns = [v for v in vulns] if vulns else []
        self._type = type
    
    def __str__(self):
        return f"The {self.type}, {self.tag}/{self.name}, at {self.loc} has {self.vulns}"

    @property
    def serial(self):
        return self._serial
    @serial.setter
    def serial(self, num):
        self._serial = num.upper() if num else num
    
    @property
    def tag(self):
        return self._tag
    @tag.setter
    def tag(self, tag):
        self._tag = tag.upper() if tag else tag

    @property
    def loc(self):
        return self._loc
    @loc.setter
    def loc(self, location):
        self._loc = location.upper() if location else location
    
    @property
    def alias(self):
        return self._alias
    @alias.setter
    def alias(self, alias):
        self._alias = alias.upper() if alias else alias
    
    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, name):
        self._name = name.upper() if name else name
    
    @property
    def count(self):
        return self._count
    @count.setter
    def count(self, count):
        self._count = count
    
    @property
    def user(self):
        return self._user
    @user.setter
    def user(self, u):
        self._user = u.upper() if u else u

    @property
    def vulns(self):
        return self._vulns
    @vulns.setter
    def vulns(self, v):
        if type(v) == list:
            self._vulns += v
        else:
            self._vulns.append(v)

    @property
    def type(self):
        return self._type
    @type.setter
    def type(self, t):
        self._type = t
    
def get_snipe(endpoint):
    URL = f"https://jrcb-snipe-it.byu.edu/api/v1/{endpoint}"
    HEADERS = {"Authorization":"Bearer " + settings["SNIPE_TOKEN"],"Content-Type":"application/json","Accept":"application/json"}
    all_rows = []
    offset = 0
    while True:
        new_url = f"{URL}?limit=500&offset={offset}"
        req = requests.get(url = new_url, headers = HEADERS)
        response = req.json()
        total = response.get("total", 0)
        rows = response.get("rows", [])
        all_rows.extend(rows)
        if len(rows) < 500 or offset + len(rows) >= total:
            break
        offset += 500
    return all_rows

def parse_snipe_assets():
    assets = get_snipe("hardware")
    mapping = []
    for asset in assets:
        if not asset["category"]["name"] in ["Printer", "Monitors"]:
            m_user = asset["assigned_to"]["name"] if asset["assigned_to"] and asset["assigned_to"]["type"] == "user" else None
            new_mach = Machine(
                serial_num=asset["serial"],
                name=asset["name"],
                tag=asset["asset_tag"],
                type=asset["category"]["name"],
                user=m_user
            )
            if asset["location"]:
                new_mach.loc = asset['location']['name']
            elif asset["rtd_location"]:
                new_mach.loc = asset['rtd_location']['name']
            else:
                new_mach.loc = f"{re.findall(r'[0-9a-zA-Z]+', new_mach.name)[0]} JRCB"
            mapping.append(new_mach)
    return mapping

def parse_snipe_users():
    users = get_snipe("users")
    mapping = []
    for user in users:
        new_user = User(name=user["name"])
        try:
            new_user.loc=user["location"]["name"]
            mapping.append(new_user)
        except:
            pass
    return mapping

def get_okta():
    URL = "https://ces-byulaw-admin.okta.com/api/v1/users"
    HEADERS = {"Authorization":"SSWS " + settings["OKTA_TOKEN"],"Accept":"application/json"}
    users = []
    while URL:
        r = requests.get(url = URL, headers = HEADERS)
        users += r.json()

        link_header = r.headers["link"]
        if link_header:
            match = r.links.get('next', {}).get('url')
            URL = match if match else None
        else:
            URL = None
    return users

def parse_okta():
    users = get_okta()
    mapping = {}
    for user in users:
        profile = user['profile']
        if not "student" in "".join([pos for pos in profile['position']]):
            mapping[f'{profile["firstName"]} {profile["lastName"]}'] = {"login":profile["login"], "email":profile["email"]}
    return mapping

def td_client():
    url = "https://api.threatdown.com"

    client_scope = ["read", "write", "execute"]
    headers = {"accountid": settings["TD_ACCOUNT"]}
    client = BackendApplicationClient(client_id=settings["TD_CLIENT_ID"], scope=client_scope)
    session = OAuth2Session(client=client, scope=client_scope)
    session.headers.update(headers)
    
    try:
        token = session.fetch_token(
            token_url=f"{url}/oauth2/token",
            client_secret=settings["TD_CLIENT_SECRET"],
            scope=" ".join(client_scope)
        )
        return session
    except Exception as e:
        raise

def get_vuln_reports():
    client = td_client()
    url = "https://api.threatdown.com"
    page_size = 2000
    url = f"{url}/nebula/v1/reports/{settings['VULN_REPORT_ID']}"
    
    HEADERS = {"content-type":"application/json",
               "authorization": f'Bearer {client.token["access_token"]}',
               "accountid":settings["TD_ACCOUNT"]}
    exp_url = "https://api.threatdown.com/nebula/v1/cve/export"
    exp_report = []
    exp_body = {
        "format":"json",
        "download":True,
        "select":[{"field":"host_name","newField":"Name"},
                {"field":"product","newField":"Application"},
                {"field":"machine_id","newField":"Machine_ID"},
                {"field":"alias","newField":"Alias"},
                {"field":"fully_qualified_host_name","newField":"Full_Hostname"}],
        "groups":[{"installation_date_after":"2000-01-01T12:00:00Z"},{"page_size":page_size}]
    }

    exp_report += client.post(exp_url, headers = HEADERS, data=json.dumps(exp_body)).json()
    return exp_report

def parse_vulns():
    vulns = get_vuln_reports()
    mapping = {}
    for vuln in vulns:
        name = vuln["Name"]
        app = vuln["Application"]
        id = vuln["Machine_ID"]
        try:
            alias = vuln["Alias"]
        except:
            alias = None
        try:
            mapping[name.upper()]["apps"] += [app] if not app in mapping[name]["apps"] else []
        except:
            mapping[name.upper()] = {"apps":[app],"alias":alias.upper() if alias else None,"id":id}
    return mapping

def get_endpoint_reports(endpoints):
    client = td_client()
    endpoint_ids = [endpoints[endpoint]["id"] for endpoint in endpoints]
    url = "https://api.threatdown.com"
    page_size = 2000
    url = f"{url}/nebula/v1/endpoints/export"
    
    HEADERS = {"content-type":"application/json",
               "authorization": f'Bearer {client.token["access_token"]}',
               "accountid":settings["TD_ACCOUNT"]}
    exp_url = "https://api.threatdown.com/nebula/v1/endpoints/export"
    exp_report = []
    exp_body = {
        "format":"json",
        "download":True,
        "select":[{"field":"agent.host_name","newField":"hostname"},
                  {"field":"agent.serial_number","newField":"serial"}],
        "endpoints": [{"id":endpoint} for endpoint in endpoint_ids],
        "groups":[{"page_size":page_size}]
    }
    exp_report += client.post(exp_url, headers = HEADERS, data=json.dumps(exp_body)).json()
    cleaned = {}
    for endpoint in exp_report:
        name = endpoint["hostname"]
        try:
            serial = endpoint["serial"]
        except:
            serial = "CHECK ME"
        if name in cleaned.keys():
            if serial not in cleaned[name]:
                cleaned[name] += serial
        else:
            cleaned[name] = [serial]
    return cleaned

def parse_endpoints(vulns):
    endpoints = get_endpoint_reports(vulns)
    
    for vuln in vulns:
        if vuln in endpoints.keys():
            vulns[vuln]["serial"] = endpoints[vuln][0]
        else:
            vulns[vuln]["serial"] = None
    return vulns

def get_falcon():
    URL = "https://oit-humio.byu.edu/api/v1/repositories/law_oit_shared/query"
    query = '' \
    '"remediation_actions": "Microsoft" and ' \
    '"hostname": not "JRCB*" and ' \
    '"hostname": not "PROX" | groupBy(hostname, limit="max") | sort(_count)'
    payload = {
        "queryString":query,
        "start":"31days",
        "end":"now",
        "isLive":False
    }
    HEADERS = {
        "Authorization":f"Bearer {settings['FALCON_TOKEN']}",
        "Content-Type":"application/json",
        "Accept":"application/json"
    }
    response = requests.post(URL, headers=HEADERS, data=json.dumps(payload)).json()
    print(response)
    return response

def parse_falcon():
    assets = get_falcon()
    mapping = [Machine(name=asset["hostname"],falcon_count=int(asset["_count"])) for asset in assets]
    return mapping

def vuln_to_mach(vulns, machines):
    serial_indexed_machines = {machine.serial:machine for machine in machines}
    name_indexed_machines = {machine.name:machine for machine in machines}
    for machine in machines:
        if not machine.alias in name_indexed_machines:
            name_indexed_machines[machine.alias] = machine
    for endpoint in vulns:
        serial = vulns[endpoint]["serial"]
        if serial in serial_indexed_machines.keys():
            machine = serial_indexed_machines[serial]
            machine.vulns = [app for app in vulns[endpoint]["apps"]]
        elif endpoint in name_indexed_machines.keys():
            machine = name_indexed_machines[endpoint]
            machine.vulns = [app for app in vulns[endpoint]["apps"]]
        else:
            machines += [Machine(name=endpoint, vulns=vulns[endpoint]["apps"])]
    vuln_machines = []
    for mach in machines:
        if len(mach.vulns) > 0:
            vuln_machines.append(mach)
    return vuln_machines

def mach_to_user(machines, users):
    loc_pattern = r"([0-9]+[a-zA-Z]*\s[a-zA-Z]+)"
    loc_indexed_users = {re.findall(loc_pattern, user.loc)[0]:user for user in users}
    name_indexed_users = {user.name:user for user in users}
    for mach in machines:
        if mach.user:
            best_user, u_score = find_match(mach.user, name_indexed_users.keys())
            if u_score >= 0.8:
                name_indexed_users[best_user].machines = mach
            else:
                name_indexed_users[settings["CATCHALL_USER"]].machines = mach
        else:
            name_indexed_users[settings["CATCHALL_USER"]].machines = mach
    users_with_vulns = []
    for user in users:
        if len(user.machines) > 0:
            users_with_vulns.append(user)
    return users_with_vulns

def users_to_email(users, profiles):
    for user in users:
        best_name, n_score = find_match(user.name, profiles.keys())
        if n_score >= 0.8:
            user.email = profiles[best_name]["email"]
        elif user.name == settings["CATCHALL_USER"]:
            catchall = user
            user.email = settings["CATCHALL_EMAIL"]
    users_with_emails = []
    for user in users:
        if user.email:
            users_with_emails.append(user)
        else:
            catchall.machines = user.machines
    return users_with_emails

def send_emails(users=[], r=None):
    rows = r if r else []
    for user in users:
        for machine in user.machines:
            rows.append({
                "user": user.name,
                "machine": machine.name,
                "vulns": ', '.join(machine.vulns) if machine.vulns else ''
            })
        message = user.format_email()
        if message:
            msg = EmailMessage()
            msg.set_content(f"{message}")
            msg['Subject'] = "Security Updates"
            msg['From'] = settings["CATCHALL_EMAIL"]
            msg['To'] = settings["SENDER_EMAIL"] # user.email

            with smtplib.SMTP("smtp.gmail.com", 587) as s:
                s.starttls()
                s.login(settings["SENDER_EMAIL"], settings["GOOGLE_PSSWD"])
                s.send_message(msg)
                s.quit()
    df = pandas.DataFrame(rows)
    msg = EmailMessage()
    master_csv = get_csv_file(df)
    msg.add_attachment(
        master_csv.read(),
        maintype='text',
        subtype='csv',
        filename='vulnerabilities_masterlist.csv')
    msg['Subject'] = "Security Updates"
    msg['From'] = settings["CATCHALL_EMAIL"]
    msg['To'] = ["CATCHALL_EMAIL"]

    with smtplib.SMTP("smtp.gmail.com", 587) as s:
        s.starttls()
        s.login(settings["SENDER_EMAIL"], settings["GOOGLE_PSSWD"])
        s.send_message(msg)
        s.quit()

def get_csv_file(df: pandas.DataFrame) -> io.StringIO:
    print(df)
    buffer = io.BytesIO()
    buffer.write(df.to_csv(index=False).encode('utf-8'))
    buffer.seek(0)
    return buffer

def compare_names(n1, n2):
    score = SequenceMatcher(None, n1.upper(), n2.upper()).ratio()
    return score

def find_match(name, names):
    best_match = ""
    best_score = 0.0
    for n in names:
        score = compare_names(name, n)
        if score > best_score:
            best_score = score
            best_match = n
    return best_match, best_score

def main():
    month = int(datetime.datetime.now().month)
    if month % 2 == 1:
        assets = parse_snipe_assets()
        users = parse_snipe_users()
        profiles = parse_okta()
        # First Last: {login: addr, email: addr}
        vulns = parse_vulns()
        # Machine: {apps: vulns, alias: name, id: machine_id}
        endpoints = parse_endpoints(vulns)
        # Machine: {apps: vulns, alias: name, id: machine_id, serial: serial_num}
        vuln_machs = vuln_to_mach(endpoints, assets)
        vuln_users = mach_to_user(vuln_machs, users)
        emails = users_to_email(vuln_users, profiles)
        send_emails(emails)
    else:
        internal = parse_falcon()
        # List of Machines
        send_emails(r=[[mach.name, mach.count] for mach in internal])

if __name__ == "__main__":
    main()
