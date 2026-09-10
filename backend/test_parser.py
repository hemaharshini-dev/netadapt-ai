from parsers.cisco_parser import CiscoConfigParser


configs = [
    "configs/cisco/compliant.cfg",
    "configs/cisco/mixed.cfg",
    "configs/cisco/noncompliant.cfg"
]

parser = CiscoConfigParser()

for config_path in configs:

    print("\n" + "=" * 60)
    print(f"CONFIG: {config_path}")
    print("=" * 60)

    result = parser.parse_file(config_path)

    print(result)