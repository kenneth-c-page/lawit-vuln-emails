#!/usr/bin/env python3


"""automate bi-monthly emails to Law School faculty"""

from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from json import dumps
from re import findall
from typing import List, Optional

from requests import get, post
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from devopsdriver import Settings


@dataclass
class Assignee:
    """A person"""

    name: Optional[str] = None
    email: Optional[str] = None
    loc: Optional[str] = None
    cat: Optional[str] = None
    machines: List = field(default_factory=list)

    def __post_init__(self):
        # Ensure machines is always a list
        if not isinstance(self.machines, list):
            self.machines = [self.machines] if self.machines else []

    @property
    def type(self) -> Optional[str]:
        """assignee.type"""
        return self.cat

    @type.setter
    def type(self, value: str):
        """assignee,type ="""
        if not isinstance(value, str):
            raise TypeError(f"{value} is NOT a string.")

        self.cat = value

    def add_machines(self, machines):
        """Add one or more machines to the assignee's list."""
        if isinstance(machines, list):
            self.machines.extend(machines)
        else:
            self.machines.append(machines)

    def format_email(self, settings: Settings) -> str:
        """Format email content based on machine vulnerabilities."""
        if not self.machines:
            return ""

        formatted_vulnerabilities = []

        for machine in self.machines:
            if not machine.get_vulns():
                continue

            sanitized = set()  # Use set to avoid duplicate Adobe entries

            for vuln in machine.get_vulns():
                for partial, value in settings["sanitized"].items():
                    if partial in vuln:
                        vuln = value
                        break

                sanitized.add(vuln)

            vulns = settings["vulnerability"].format(
                machine.tag, "\n".join(f"\t- {vuln}" for vuln in sanitized)
            )
            formatted_vulnerabilities.append(vulns)

        return settings["email body"].format(
            self.name.split()[0].title() if self.name else settings["unknown user"],
            "\n".join(formatted_vulnerabilities),
        )


class Machine:  # pylint: disable=too-many-instance-attributes
    """Represents a single machine."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        name=None,
        users=None,
        loc=None,
        tag=None,
        vulns=None,
        alias=None,
        falcon_count=0,
    ):
        self.name = name
        self.users = users if isinstance(users, list) else [users] if users else []
        self.loc = loc
        self.tag = tag
        self.vulns = vulns if isinstance(vulns, list) else [vulns] if vulns else []
        self.alias = alias
        self.falcon_count = falcon_count
        self.assigned = bool(self.users)

    def add_users(self, users):
        """Add one or more users to the machine."""
        users = users if isinstance(users, list) else [users]
        self.users.extend(users)
        self.assigned = bool(self.users)

    def add_vulns(self, vulns):
        """Add one or more vulnerabilities to the machine."""
        vulns = vulns if isinstance(vulns, list) else [vulns]
        self.vulns.extend(vulns)

    # Use properties to simplify getter/setter methods
    @property
    def users(self):
        """machine.users"""
        return self._users

    @users.setter
    def users(self, value):
        """machine.users ="""
        self._users = value if isinstance(value, list) else [value] if value else []
        self.assigned = bool(self._users)

    @property
    def vulns(self):
        """machine.vulns"""
        return self._vulns

    @vulns.setter
    def vulns(self, value):
        """machine.vulns ="""
        self._vulns = value if isinstance(value, list) else [value] if value else []

    # Simplified assignment methods
    def assign(self):
        """Mark machine as assigned if users are present."""
        self.assigned = bool(self.users)

    def unassign(self):
        """Mark machine as unassigned and clear users."""
        self.users = []
        self.assigned = False

    def get_assignment(self):
        """Return users if assigned, else False."""
        return self.users if self.assigned else False


def get_snipe(endpoint: str, settings: Settings) -> list[str]:
    """Get snipe info from endpoint"""
    headers = {
        k: (v.format(settings["snipe.token"]) if k == "Authorization" else v)
        for k, v in settings["snipe.headers"].items()
    }
    pagination = settings["pagination"]
    all_rows = []
    offset = 0

    while True:
        new_url = settings["snipe.url"].format(endpoint, pagination, offset)
        response = get(
            url=new_url, headers=headers, timeout=settings["snipe.timeout in seconds"]
        ).json()
        total = response.get("total", 0)
        rows = response.get("rows", [])
        all_rows.extend(rows)

        if len(rows) < pagination or offset + len(rows) >= total:
            break

        offset += pagination

    return all_rows


def parse_snipe_assets(settings: Settings):
    """get hardware assets"""
    assets = get_snipe("hardware", settings)
    mapping = []

    for asset in assets:
        assignee = asset["assigned_to"]
        device = asset["name"]

        if not asset["category"]["name"] in ["Printer", "Monitors"]:
            new_mach = Machine(name=device, users=assignee, tag=asset["asset_tag"])

            if asset["location"] or asset["rtd_location"]:
                try:
                    new_mach.loc = asset["location"]["name"]

                except Exception:  # pylint: disable=broad-exception-caught
                    new_mach.loc = asset["rtd_location"]["name"]

            elif asset["status_label"]["status_type"] == "pending":
                new_mach.loc = f"{findall(r"[0-9a-zA-Z]+", device)[0]} JRCB"

            mapping.append(new_mach)

    return mapping


def parse_snipe_users(settings: Settings):
    """get snipe users"""
    users = get_snipe("users", settings)
    mapping = []

    for user in users:
        try:
            new_user = Assignee(name=user["name"], loc=user["location"]["name"])
            mapping.append(new_user)

        except Exception:  # pylint: disable=broad-exception-caught
            pass

    return mapping


def get_okta(settings: Settings):
    """get okta response"""
    headers = {
        k: (v.format(settings["okta.token"]) if k == "Authorization" else v)
        for k, v in settings["okta.headers"].items()
    }
    users = []
    url = settings["okta.url"]

    while True:
        r = get(
            url=url,
            headers=headers,
            timeout=settings["okta.timeout in seconds"],
        )
        users += r.json()
        link_header = r.headers["link"]

        if not link_header:
            break

        url = r.links.get("next", {}).get("url")

        if not url:
            break

    return users


def parse_okta(settings: Settings):
    """parse users"""
    users = get_okta(settings)
    mapping = {}

    for user in users:
        profile = user["profile"]

        if "student" not in "".join(pos for pos in profile["position"]):
            mapping[f"{profile["firstName"]} {profile["lastName"]}"] = {
                "login": profile["login"],
                "email": profile["email"],
            }

    return mapping


def get_oauth_session(
    url: str, client_id: str, client_secret: str, account_id: str
) -> OAuth2Session:
    """Authenticate and return an OAuth2 session client."""
    client_scope = [
        "read",
        "write",
        "execute",
    ]  # Adjust scopes based on API requirements
    client = BackendApplicationClient(client_id=client_id, scope=client_scope)
    session = OAuth2Session(client=client, scope=client_scope)
    session.headers.update({"accountid": account_id})
    token = session.fetch_token(
        token_url=url,
        client_secret=client_secret,
        scope=" ".join(client_scope),
    )
    session.headers.update(
        {
            "content-type": "application/json",
            "authorization": f"Bearer {token["access_token"]}",
        }
    )
    return session


def get_threatdown(settings: Settings):
    """Fetch all reports with pagination, handling rate limits."""

    session = get_oauth_session(
        settings["threatdown.token url"],
        settings["threatdown.client"],
        settings["threatdown.secret"],
        settings["threatdown.account"],
    )
    exp_report = []
    exp_report += session.post(
        settings["export url"], data=dumps(settings["threatdown.export body"])
    ).json()
    return exp_report


def parse_threatdown(settings: Settings):
    """parse info from threatdown"""
    vulns = get_threatdown(settings)
    mapping = {}

    for vuln in vulns:
        name = vuln["Name"]
        app = vuln["Application"]

        try:
            alias = vuln["Alias"]

        except Exception:  # pylint: disable=broad-exception-caught
            alias = None

        try:
            mapping[name.upper()]["apps"] += (
                [app] if not app in mapping[name]["apps"] else []
            )

        except Exception:  # pylint: disable=broad-exception-caught
            mapping[name.upper()] = {
                "apps": [app],
                "alias": alias.upper() if alias else None,
            }

    return mapping


def get_falcon(settings: Settings):
    """get falcon info"""
    headers = {
        k: (v.format(settings["falcon.token"]) if k == "Authorization" else v)
        for k, v in settings["falcon.headers"].items()
    }
    response = post(
        settings["falcon.url"],
        headers=headers,
        data=dumps(settings["falcon.payload"]),
        timeout=settings["falcon.timeout in seconds"],
    ).json()
    return response


def parse_falcon(settings: Settings):
    """parse falcon info"""
    assets = get_falcon(settings)
    mapping = [
        Machine(name=asset["hostname"], falcon_count=int(asset["_count"]))
        for asset in assets
    ]
    return mapping


def falcon_email():
    """do something amazing, i guess"""


def add_okta_emails(mapping, users):
    """add the emails"""
    for user in users:
        name = user.get_name()
        match, score = find_match(name, mapping.keys())

        if score >= 0.8:
            user.set_email(mapping[match]["email"])


def add_vulns(mapping, machines):
    """add vulnerabilities"""
    for machine in machines:
        vulns = []
        name = machine.get_name()
        alias = machine.get_alias()

        try:
            try:
                try:
                    vulns = mapping[name]["apps"]
                except Exception:  # pylint: disable=broad-exception-caught
                    if alias:
                        vulns = mapping[alias]["apps"]
            except Exception:  # pylint: disable=broad-exception-caught
                try:
                    n_match, n_score = find_match(name, mapping.keys())

                    if n_score >= 0.8:
                        vulns = mapping[n_match]["apps"]
                    else:
                        if alias:
                            a_match, a_score = find_match(alias, mapping)

                            if a_score >= 0.8:
                                vulns = mapping[a_match]["apps"]
                except Exception:  # pylint: disable=broad-exception-caught
                    vulns = []
        except Exception:  # pylint: disable=broad-exception-caught
            vulns = []

        machine.set_vulns(vulns)


def map_machines(users, machine_list):
    """map machines"""
    no_loc_m = []

    for machine in machine_list:
        mach_loc = None

        try:
            mach_loc = machine.get_location().upper()

        except Exception:  # pylint: disable=broad-exception-caught
            no_loc_m.append(machine)
            continue

        for user in users:
            u_loc = None
            try:
                u_loc = user.get_location()

            except Exception:  # pylint: disable=broad-exception-caught
                continue

            if u_loc.upper() == mach_loc.upper():
                if machine not in user.get_machines():
                    user.add_machines(machine)
                    machine.add_users(user.get_name())

        if not machine.get_assignment():
            no_loc_m.append(machine)

    users.append(
        Assignee(
            name="459 JRCB",
            cat="loc",
            machines=list(no_loc_m),
            loc="459 JRCB",
            email="",
        )
    )


def send_emails(users):
    """send emails"""
    with open("vuln2.0", "w", encoding="utf-8") as f:
        f.write("")

    for user in users:
        email = user.format_email()

        with open("vuln2.0", "a", encoding="utf-8") as f:
            f.write(f"{email}\n")


def compare_names(n1, n2):
    """compare em"""
    score = SequenceMatcher(None, n1.upper(), n2.upper()).ratio()
    return score


def find_match(name, names):
    """find best match"""
    best_match = ""
    best_score = 0.0

    for n in names:
        score = compare_names(name, n)

        if score > best_score:
            best_score = score
            best_match = n

    return best_match, best_score


def main():
    """lets go"""
    settings = Settings(__file__)
    month = int(datetime.now().month)
    users = parse_snipe_users(settings)

    if month % 2 == 1:
        assets = parse_snipe_assets(settings)
        users_to_emails = parse_okta(settings)
        add_okta_emails(users_to_emails, users)
        vulns = parse_threatdown(settings)
        add_vulns(vulns, assets)
        ####### NEXT STEPS #######
        map_machines(users, assets)
        send_emails(users)
    else:
        assets = parse_falcon(settings)
        vulns = parse_threatdown(settings)
        add_vulns(vulns, assets)
        falcon_email()  # DEFINE


if __name__ == "__main__":
    main()
