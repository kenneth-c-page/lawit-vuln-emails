import requests
import json
import re
import smtplib
import time
from difflib import SequenceMatcher
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from email.message import EmailMessage
from email.mime.text import MIMEText

def main():
    # name : {login : addr, email : addr}
    name_to_email = parse_okta()

    # asset : {assignee : name, loc_type : type}
    device_to_location = parse_snipe_assets()
    
    # location_name : [all_users_in_loc]
    snipe_users = parse_snipe_users()

    # assest: vulnerable applications
    vulns = parse_threatdown()

    # asset : [all_applicable_users]
    asset_to_user = map_asset_to_user(device_to_location, snipe_users)

    # asset : {users : [all_users], vulnerabilities : [all_vulnerable_applications]}
    expanded_assets = expand_assets(asset_to_user, vulns)

    # email : {name : name, updates : {asset_name : [all_vulnerable_apps]}}
    email_mapping = map_asset_to_emails(expanded_assets, name_to_email)
    
    emails = format_emails(email_mapping)
    with open("vuln1.0", "w") as f:
        f.write("")
    for email in emails:
        addr = [key for key in email.keys()][0]
        send_email(email[addr])
        time.sleep(2)

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
    mapping = {}
    for asset in assets:
        assignee = asset["assigned_to"]
        device = asset["name"]
        if not asset["category"]["name"] in ["Printer", "Monitors"]:
            if (asset["location"] or asset["rtd_location"]):
                try:
                    mapping[device] = {"loc":asset["location"]["name"],"tag":asset["asset_tag"]}
                except:
                    mapping[device] = {"loc":asset["rtd_location"]["name"],"tag":asset["asset_tag"]}
            elif asset["status_label"]["status_type"] == "pending":
                mapping[device] = {"loc":f"{re.findall(r"[0-9a-zA-Z]+", device)[0]} JRCB","tag":asset["asset_tag"]}
    return mapping

def parse_snipe_users():
    users = get_snipe("users")
    mapping = {}
    for user in users:
        try:
            mapping[user["location"]["name"]] += [user["name"]]
        except:
            try:
                mapping[user["location"]["name"]] = [user["name"]]
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

def map_asset_to_user(device_map, user_map):
    # asset : loc
    # location_name : [all_users_in_loc]
    mapping = {}
    for asset in device_map.keys():
        loc = device_map[asset]["loc"]
        tag = device_map[asset]["tag"]
        try:
            mapping[asset.upper()] = {"users":[user.upper() for user in user_map[loc]],"tag":tag}
        except:
            mapping[asset.upper()] = {"users":[loc.upper()],"tag":tag}
    return mapping

def map_asset_to_emails(devices_to_users, users_to_email):
    # asset : {users : [all_users], vulnerabilities : [all_vulnerable_applications]}
    # name : {login : addr, email : addr}
    # email : {name : name, updates : {asset_name : [all_vulnerable_apps]}}
    mapping = {}
    users_to_vulnerabilities = {}
    for asset in devices_to_users:
        for user in devices_to_users[asset]["users"]:
            try:
                users_to_vulnerabilities[user][asset] = {"vulns":devices_to_users[asset]["vulnerabilities"],"tag":devices_to_users[asset]["tag"]}
            except:
                users_to_vulnerabilities[user] = {asset:{"vulns":devices_to_users[asset]["vulnerabilities"],"tag":devices_to_users[asset]["tag"]}}
    names = users_to_email.keys()
    for user in users_to_vulnerabilities:
        if len(re.findall(f"[0-9]+", user)) == 0:
            match, score = compare_names(user, names)
            if score >= 0.8:
                # names is from email keys
                mapping[users_to_email[match]["email"]] = {user:users_to_vulnerabilities[user]}
        else:
            mapping[user] = {user:users_to_vulnerabilities[user]}
    accounted_vulns = 0
    for email in mapping:
        accounted_vulns+=len(mapping[email].keys())
    return mapping
    
def expand_assets(asset_to_users, vulns):
    unused_threatdown = []
    expanded_assets = {}
    for asset in vulns:
        try:
            try:
                expanded_assets[asset] = {"users":asset_to_users[asset]["users"], "vulnerabilities":vulns[asset]["apps"], "tag":asset_to_users[asset]["tag"]}
            except:
                expanded_assets[vulns[asset]["alias"]] = {"users":asset_to_users[vulns[asset]["alias"]]["users"], "vulnerabilities":vulns[asset]["apps"], "tag":asset_to_users[vulns[asset]["alias"]]["tag"]}
        except:
            best_match, score = compare_names(asset, asset_to_users)
            if score >= 0.8:
                if not best_match in expanded_assets.keys():
                    expanded_assets[best_match] = {"users":asset_to_users[best_match]["users"], "vulnerabilities":vulns[asset]["apps"], "tag":asset_to_users[best_match]["tag"]}
                else:
                    unused_threatdown.append(asset)
            else:
                unused_threatdown.append(asset)
    return expanded_assets

def match_names(name1, names):
    n1 = name1.lower().split(" ")
    for name in names:
        n2 = name.lower().split(" ")
        overlap = list(set(n1) & set(n2))
        if len(overlap) >= 2:
            return overlap
    return False

def compare_names(name, names):
    best_match = ""
    best_score = 0.0
    for n in names:
        score = SequenceMatcher(None, n.upper(), name.upper()).ratio()
        if score > best_score:
            best_score = score
            best_match = n
    return best_match, best_score

def format_emails(contents):
    # email : {name : {asset_name : [all_vulnerable_apps]}}
    emails = []
    for addr in contents:
        to_use = contents[addr]
        name = [name for name in to_use.keys()][0]
        assets = to_use[name].keys()
        formatted_vulnerabilities = []
        for asset in assets:
            sanitized = ""
            for vuln in to_use[name][asset]["vulns"]:
                if "Adobe" in vuln:
                    if not "Adobe" in sanitized:
                        sanitized += f"\n\t- Adobe Products"
                else:
                    sanitized += f"\n\t- {vuln}"
            vulns = f"The device labeled {to_use[name][asset]["tag"]} has the following vulnerabilities that need to be updated or removed:\n\t- A Windows/Mac system update if available{sanitized}"
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
        """.format(name.split()[0].title(), f"\n".join(formatted_vulnerabilities))
        emails.append({addr:content})
    return emails

def send_email(contents):
    with open("vuln1.0", "a") as f:
        f.write(f"{contents}\n")
    # msg = EmailMessage()
    # msg.set_content(f"{contents}")
    # msg['Subject'] = "test"
    # msg['From'] = ""
    # msg['To'] = ''

    # with smtplib.SMTP("smtp.gmail.com", 587) as s:
    #     s.starttls()
    #     s.login("", "")
    #     s.send_message(msg)
    #     s.quit()
    pass

if __name__ == "__main__":
    main()
