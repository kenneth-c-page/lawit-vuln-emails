import requests
import json
import re
import smtplib
import time
import datetime
from difflib import SequenceMatcher
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from email.message import EmailMessage
from email.mime.text import MIMEText

class Assignee():
    def __init__(self, cat=None, machines=None, name=None, email=None, loc=None):
        self.cat = cat
        self.machines = machines if machines is not None else []
        self.name = name
        self.email = email
        self.loc = loc

    def set_type(self, cat):
        if type(cat) == str:
            self.cat = cat
        else:
            raise TypeError(f"{cat} is NOT a string.")
        
    def set_machines(self, machines):
        if type(machines) == list:
            self.machines = machines
        else:
            self.machines = [machines]
    
    def add_machines(self, machines):
        if type(machines) == list:
            self.machines += machines
        else:
            self.machines.append(machines)
    
    def set_location(self, loc):
        self.loc = loc
    
    def set_name(self, name):
        self.name = f"{name}"
    
    def set_email(self, email):
        self.email = f"{email}"
    
    def get_type(self):
        return self.cat
    
    def get_name(self):
        return self.name
    
    def get_machines(self):
        return self.machines
    
    def get_email(self):
        return self.email
    
    def get_location(self):
        return self.loc
    
    def format_email(self):
        if self.machines:
            formatted_vulnerabilities = []
            for machine in self.machines:
                sanitized = ""
                if len(machine.get_vulns()) > 0:
                    for vuln in machine.get_vulns():
                        if "Adobe" in vuln:
                            if not "Adobe" in sanitized:
                                sanitized += f"\n\t- Adobe Products"
                        else:
                            sanitized += f"\n\t- {vuln}"
                    vulns = f"The device labeled {machine.tag} has the following vulnerabilities that need to be updated or removed:\n\t- A Windows/Mac system update if available{sanitized}"
                    formatted_vulnerabilities.append(vulns)
            content = """
Hi {0}!

In an effort to protect you and important assets, we are emailing you because your law school computer(s) has/have been found with the following vulnerabilities:

{1}

If you use these programs, please update them at your earliest convenience. However, if you do not use these programs, please remove them from your device.

If you have any questions or need help with removing these vulnerabilities, please feel free to email, call, or visit us at the Help Desk.

Thank you!
Best regards,
Kenneth Page
        """.format(self.name.split()[0].title(), f"\n".join(formatted_vulnerabilities))
            return content

class Machine():
    def __init__(self, name=None, users=None, loc=None, tag=None, vulns=None, alias=None, falcon_count=None):
        self.users = users if users is not None else []
        self.loc = loc
        self.tag = tag
        self.vulns = vulns if vulns is not None else []
        self.name = name
        self.alias = alias
        self.assigned = True if self.users else False
        self.falcon_count = falcon_count if falcon_count is not None else 0

    def set_users(self, user_list):
        if type(user_list) == list:
            self.users = user_list
        else:
            self.users = [user_list]
    
    def add_users(self, user_list):
        try:
            if type(user_list) == list:
                self.users += user_list
            else:
                self.users.append(user_list)
        except:
            self.users = user_list if type(user_list) == list else [user_list]

    def set_vulns(self, vuln_list):
        if type(vuln_list) == list:
            self.vulns = vuln_list
        else:
            self.vulns = [vuln_list]
    
    def add_vulns(self, vuln_list):
        try:
            if type(vuln_list) == list:
                self.vulns += vuln_list
            else:
                self.vulns.append(vuln_list)
        except:
            self.vulns = vuln_list if type(vuln_list) == list else [vuln_list]
    
    def set_tag(self, tag):
        self.tag = tag
    
    def set_loc(self, loc):
        self.loc = loc

    def set_alias(self, alias):
        self.alias = alias
    
    def set_falcon_count(self, count):
        self.falcon_count = count

    def get_users(self):
        return self.users
    
    def get_location(self):
        return self.loc
    
    def get_vulns(self):
        return self.vulns
    
    def get_tag(self):
        return self.tag
    
    def get_alias(self):
        return self.alias
    
    def get_name(self):
        return self.name

    def assgin(self):
        self.assign = True
    
    def unassign(self):
        self.assign = False
    
    def get_assignment(self):
        return self.users if self.users else False
    
    def get_falcon_count(self):
        return self.falcon_count

def get_snipe(endpoint):
    URL = f"https://jrcb-snipe-it.byu.edu/api/v1/{endpoint}"
    api_token = ""
    HEADERS = {"Authorization":"Bearer " + api_token,"Content-Type":"application/json","Accept":"application/json"}
    all_rows = []
    offset = 0
    while True:
        new_url = f"{URL}?limit=500&offset={offset}"
        response = requests.get(url = new_url, headers = HEADERS).json()
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
        assignee = asset["assigned_to"]
        device = asset["name"]
        if not asset["category"]["name"] in ["Printer", "Monitors"]:
            new_mach = Machine(name=device, users=assignee, tag=asset["asset_tag"])

            if (asset["location"] or asset["rtd_location"]):
                try:
                    new_mach.set_loc(asset["location"]["name"])
                except:
                    new_mach.set_loc(asset["rtd_location"]["name"])
            elif asset["status_label"]["status_type"] == "pending":
                new_mach.set_loc(f"{re.findall(r"[0-9a-zA-Z]+", device)[0]} JRCB")
            mapping.append(new_mach)
    return mapping

def parse_snipe_users():
    users = get_snipe("users")
    mapping = []
    for user in users:
        try:
            new_user = Assignee(name=user["name"], loc=user["location"]["name"])
            mapping.append(new_user)
        except:
            pass
    return mapping

def get_okta():
    URL = "https://ces-byulaw-admin.okta.com/api/v1/users"
    api_token = ""
    HEADERS = {"Authorization":"SSWS " + api_token,"Accept":"application/json"}
    users = []
    while URL:
        r = requests.get(url = URL, headers = HEADERS)
        users += r.json()

        link_header = r.headers["link"]
        if link_header:# and 'rel="next"' in link_header:
            # match = re.findall(r'<([^>]+)>; rel="next"', link_header)
            match = r.links.get('next', {}).get('url')
            # URL = match[0] if match else None
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
            mapping[f"{profile["firstName"]} {profile["lastName"]}"] = {"login":profile["login"], "email":profile["email"]}
        # mapping[f"{user["displayName"]}"] = {"login":profile["login"], "email":profile["email"]}
    return mapping

def get_threatdown():
    # Replace with your actual credentials from ThreatDown OneView
    ACCOUNT_ID = ""
    CLIENT_ID = ""
    CLIENT_SECRET = ""

    # Base URL for ThreatDown API
    BASE_URL = "https://api.threatdown.com"
    REPORT_ID = ""

    def get_oauth_client(client_id, client_secret, account_id):
        """Authenticate and return an OAuth2 session client."""
        client_scope = ["read", "write", "execute"]  # Adjust scopes based on API requirements
        headers = {"accountid": account_id}
        
        client = BackendApplicationClient(client_id=client_id, scope=client_scope)
        session = OAuth2Session(client=client, scope=client_scope)
        session.headers.update(headers)
        
        try:
            token = session.fetch_token(
                token_url=f"{BASE_URL}/oauth2/token",
                client_secret=client_secret,
                scope=" ".join(client_scope)
            )
            return session
        except Exception as e:
            raise

    def get_all_reports(client):
        """Fetch all reports with pagination, handling rate limits."""
        reports = []
        next_cursor = ""
        page_size = 1000  # Adjust based on API limits or documentation
        url = f"{BASE_URL}/nebula/v1/reports/{REPORT_ID}"
        token = client.fetch_token(
                token_url=f"{BASE_URL}/oauth2/token",
                client_secret=CLIENT_SECRET,
                scope=" ".join(["read", "write", "execute"]))
        HEADERS = {"content-type":"application/json","authorization": f"Bearer {token["access_token"]}","accountid":ACCOUNT_ID}

        exp_url = "https://api.threatdown.com/nebula/v1/cve/export"
        exp_report = []
        # while True:
        EXP_BODY = {
            "format":"json",
            "download":True,
            "select":[{"field":"host_name","newField":"Name"},
                    {"field":"product","newField":"Application"},
                    {"field":"machine_id","newField":"Machine_ID"},
                    {"field":"alias","newField":"Alias"},
                    {"field":"fully_qualified_host_name","newField":"Full_Hostname"}],
            "groups":[{"installation_date_after":"2000-01-01T12:00:00Z"},{"page_size":2000}]
        }

        exp_report += client.post(exp_url, headers = HEADERS, data=json.dumps(EXP_BODY)).json()
        return exp_report
    
    return get_all_reports(get_oauth_client(CLIENT_ID, CLIENT_SECRET, ACCOUNT_ID))

def parse_threatdown():
    vulns = get_threatdown()
    mapping = {}
    for vuln in vulns:
        name = vuln["Name"]
        app = vuln["Application"]
        try:
            alias = vuln["Alias"]
        except:
            alias = None
        try:
            mapping[name.upper()]["apps"] += [app] if not app in mapping[name]["apps"] else []
        except:
            mapping[name.upper()] = {"apps":[app],"alias":alias.upper() if alias else None}
    return mapping

def get_falcon():
    falcon_token = ""
    URL = "https://oit-humio.byu.edu/api/v1/repositories/law_oit_shared/query"
    query = '"remediation_actions": "Microsoft" and "hostname": not "JRCB*" and "hostname": not "PROX" | groupBy(hostname, limit="max") | sort(_count)'
    payload = {
        "queryString":query,
        "start":"31days",
        "end":"now",
        "isLive":False
    }
    HEADERS = {
        "Authorization":f"Bearer {falcon_token}",
        "Content-Type":"application/json",
        "Accept":"application/json"
    }
    response = requests.post(URL, headers=HEADERS, data=json.dumps(payload)).json()
    return response

def parse_falcon():
    assets = get_falcon()
    mapping = [Machine(name=asset["hostname"],falcon_count=int(asset["_count"])) for asset in assets]
    return mapping

def falcon_email():
    pass

def add_okta_emails(mapping, users):
    for user in users:
        name = user.get_name()
        match, score = find_match(name, mapping.keys())
        if score >= 0.8:
            user.set_email(mapping[match]["email"])

def add_vulns(mapping, machines):
    unused_threatdown = [key for key in mapping.keys()]
    for machine in machines:
        vulns = []
        name = machine.get_name()
        alias = machine.get_alias()
        try:
            try:
                try:
                    vulns = mapping[name]["apps"]
                    # unused_threatdown.remove(name)
                except:
                    if alias:
                        vulns = mapping[alias]["apps"]
                    else:
                        pass
                    # unused_threatdown.remove(alias)
                    #### ADD TO CATCH-ALL USER
            except:
                try:
                    n_match, n_score = find_match(name, mapping.keys())
                    if n_score >= 0.8:
                        vulns = mapping[n_match]["apps"]
                        # unused_threatdown.remove(n_match)
                    else:
                        if alias:
                            a_match, a_score = find_match(alias, mapping)
                            if a_score >= 0.8:
                                vulns = mapping[a_match]["apps"]
                        else:
                            pass
                                # unused_threatdown.remove(a_match)
                                #### ADD TO CATCH-ALL USER
                except:
                    vulns = []
        except:
            vulns=[]
        machine.set_vulns(vulns)

def map_machines(users, machine_list):
    no_loc_u = []
    no_loc_m = []
    re_pattern = r"([0-9]+[a-zA-Z]*\s[a-zA-Z]+)"
    for machine in machine_list:
        mach_loc = None
        try:
            mach_loc = machine.get_location().upper()
        except:
            no_loc_m.append(machine)
            continue
        for user in users:
            u_loc = None
            try:
                u_loc = user.get_location()
            except:
                continue
            if u_loc.upper() == mach_loc.upper():
                if machine not in user.get_machines():
                    user.add_machines(machine)
                    machine.add_users(user.get_name())
        if not machine.get_assignment():
            no_loc_m.append(machine)
    users.append(Assignee(name="459 JRCB", cat="loc", machines=[mach for mach in no_loc_m], loc="459 JRCB", email="helpdesk@law.byu.edu"))
            
def send_emails(users):
    with open("vuln2.0", "w") as f:
        f.write("")
    for user in users:
        email = user.format_email()
        with open("vuln2.0", "a") as f:
            f.write(f"{email}\n")
        # print(f"{user.get_email()}\n{email}")
        # msg = EmailMessage()
        # msg.set_content(f"{email}")
        # msg['Subject'] = "test"
        # msg['From'] = "helpdesk@law.byu.edu"
        # msg['To'] = 'kenneth.page@law.byu.edu'
        # # msg['To'] = user.get_email()

        # with smtplib.SMTP("smtp.gmail.com", 587) as s:
        #     s.starttls()
        #     s.login("kenneth.page@law.byu.edu", "haqe uyno ooiu newt")
        #     s.send_message(msg)
        #     s.quit()
    pass

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
    users = parse_snipe_users()
    if month % 2 == 1:
        assets = parse_snipe_assets()
        users_to_emails = parse_okta()
        add_okta_emails(users_to_emails, users)
        vulns = parse_threatdown()
        add_vulns(vulns, assets)
        ####### NEXT STEPS #######
        map_machines(users, assets)
        send_emails(users)
    else:
        assets = parse_falcon()
        vulns = parse_threatdown()
        add_vulns(vulns, assets)
        falcon_email() # DEFINE

if __name__ == "__main__":
    main()
