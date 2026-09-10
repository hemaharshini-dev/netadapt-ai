import re
from pathlib import Path


class CiscoConfigParser:
    """
    Basic Cisco IOS XE configuration parser.

    Current scope:
    - Device hostname
    - Domain name
    - AAA
    - AAA login authentication
    - Local users
    - Password encryption
    - SSH timeout
    - SSH authentication retries
    - VTY configuration
    - DHCP service
    - Logging
    - NTP authentication

    This parser extracts configuration meaning.
    It does NOT perform compliance checks.
    """

    def __init__(self):
        self.config = self._empty_config()

    def _empty_config(self):
        """
        Create a fresh normalized configuration structure.
        """

        return {
            "device": {
                "hostname": None,
                "domain_name": None
            },

            "authentication": {
                "aaa_enabled": False,
                "login_authentication": None,
                "local_users": []
            },

            "ssh": {
                "timeout": None,
                "authentication_retries": None,
                "vty": []
            },

            "services": {
                "password_encryption": False,
                "dhcp": True
            },

            "logging": {
                "enabled": False,
                "buffered": None
            },

            "ntp": {
                "authentication_enabled": False
            }
        }

    def parse_file(self, file_path):
        """
        Read and parse a Cisco configuration file.
        """

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {file_path}"
            )

        config_text = path.read_text(encoding="utf-8")

        return self.parse(config_text)

    def parse(self, config_text):
        """
        Parse Cisco configuration text.
        """

        # Start with a clean configuration every time parse()
        # is called.
        self.config = self._empty_config()

        current_context = None
        current_vty = None

        lines = config_text.splitlines()

        for raw_line in lines:

            # -----------------------------------------
            # Preserve indentation
            # -----------------------------------------

            stripped_line = raw_line.strip()

            # Ignore empty lines and Cisco comments/separators
            if not stripped_line or stripped_line.startswith("!"):
                continue

            is_indented = raw_line.startswith((" ", "\t"))

            line = stripped_line

            # -----------------------------------------
            # VTY CONTEXT
            # -----------------------------------------

            vty_match = re.match(
                r"^line\s+vty\s+(\d+)(?:\s+(\d+))?$",
                line,
                re.IGNORECASE
            )

            if vty_match:

                start = int(vty_match.group(1))

                end = (
                    int(vty_match.group(2))
                    if vty_match.group(2)
                    else start
                )

                current_context = "vty"

                current_vty = {
                    "line_range": f"{start}-{end}",
                    "transport": [],
                    "access_class": None,
                    "exec_timeout": None,
                    "login_authentication": None
                }

                self.config["ssh"]["vty"].append(current_vty)

                continue

            # -----------------------------------------
            # GLOBAL CONTEXT
            # -----------------------------------------

            if not is_indented:

                current_context = None
                current_vty = None

            # -----------------------------------------
            # VTY-SPECIFIC COMMANDS
            # -----------------------------------------

            if current_context == "vty" and current_vty:

                # transport input ssh
                transport_match = re.match(
                    r"^transport\s+input\s+(.+)$",
                    line,
                    re.IGNORECASE
                )

                if transport_match:

                    protocols = transport_match.group(1).split()

                    current_vty["transport"] = protocols

                    continue

                # access-class 10 in
                access_match = re.match(
                    r"^access-class\s+(\S+)\s+in$",
                    line,
                    re.IGNORECASE
                )

                if access_match:

                    current_vty["access_class"] = (
                        access_match.group(1)
                    )

                    continue

                # exec-timeout 10 0
                timeout_match = re.match(
                    r"^exec-timeout\s+(\d+)\s+(\d+)$",
                    line,
                    re.IGNORECASE
                )

                if timeout_match:

                    minutes = int(timeout_match.group(1))
                    seconds = int(timeout_match.group(2))

                    current_vty["exec_timeout"] = {
                        "minutes": minutes,
                        "seconds": seconds
                    }

                    continue

                # login authentication default
                login_match = re.match(
                    r"^login\s+authentication\s+(\S+)$",
                    line,
                    re.IGNORECASE
                )

                if login_match:

                    current_vty["login_authentication"] = (
                        login_match.group(1)
                    )

                    continue

            # -----------------------------------------
            # GLOBAL COMMANDS
            # -----------------------------------------

            # aaa new-model
            if line.lower() == "aaa new-model":

                self.config["authentication"]["aaa_enabled"] = True

                continue

            # aaa authentication login default local
            if line.lower().startswith(
                "aaa authentication login "
            ):

                parts = line.split()

                # Expected:
                # aaa authentication login <method-list> <method> ...

                if len(parts) >= 5:

                    method_list = parts[3]
                    methods = parts[4:]

                    self.config["authentication"][
                        "login_authentication"
                    ] = {
                        "method_list": method_list,
                        "methods": methods
                    }

                continue

            # username admin secret ...
            # username admin password ...
            if line.lower().startswith("username "):

                parts = line.split()

                if len(parts) >= 3:

                    username = parts[1]

                    if "secret" in [
                        part.lower() for part in parts
                    ]:
                        credential_type = "secret"

                    elif "password" in [
                        part.lower() for part in parts
                    ]:
                        credential_type = "password"

                    else:
                        credential_type = "unknown"

                    self.config["authentication"][
                        "local_users"
                    ].append(
                        {
                            "username": username,
                            "credential_type": credential_type
                        }
                    )

                continue

            # service password-encryption
            if line.lower() == "service password-encryption":

                self.config["services"][
                    "password_encryption"
                ] = True

                continue

            # no service dhcp
            if line.lower() == "no service dhcp":

                self.config["services"]["dhcp"] = False

                continue

            # hostname NetAdapt-Router
            if line.lower().startswith("hostname "):

                self.config["device"]["hostname"] = (
                    line.split(" ", 1)[1]
                )

                continue

            # ip domain-name example.com
            if line.lower().startswith("ip domain-name "):

                self.config["device"]["domain_name"] = (
                    line[len("ip domain-name "):].strip()
                )

                continue

            # ip ssh time-out 60
            if line.lower().startswith("ip ssh time-out "):

                parts = line.split()

                if len(parts) >= 4:

                    try:
                        value = int(parts[-1])

                        self.config["ssh"]["timeout"] = {
                            "value": value,
                            "unit": "seconds"
                        }

                    except ValueError:
                        pass

                continue

            # ip ssh authentication-retries 3
            if line.lower().startswith(
                "ip ssh authentication-retries "
            ):

                parts = line.split()

                if len(parts) >= 4:

                    try:
                        value = int(parts[-1])

                        self.config["ssh"][
                            "authentication_retries"
                        ] = value

                    except ValueError:
                        pass

                continue

            # logging enable
            if line.lower() == "logging enable":

                self.config["logging"]["enabled"] = True

                continue

            # logging buffered 64000
            if line.lower().startswith("logging buffered "):

                parts = line.split()

                if len(parts) >= 3:

                    try:
                        value = int(parts[-1])

                        self.config["logging"]["buffered"] = {
                            "enabled": True,
                            "size": value
                        }

                    except ValueError:
                        pass

                continue

            # ntp authenticate
            if line.lower() == "ntp authenticate":

                self.config["ntp"][
                    "authentication_enabled"
                ] = True

                continue

        return self.config