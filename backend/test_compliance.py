import json
from pathlib import Path

from parsers.cisco_parser import CiscoConfigParser
from compliance.engine import ComplianceEngine


RULES_PATH = Path(
    "rules/cis/cisco_ios_xe_17_v2.2.1.json"
)

CONFIGS = [
    ("configs/cisco/compliant.cfg", 15),
    ("configs/cisco/mixed.cfg", 11),
    ("configs/cisco/noncompliant.cfg", 0),
]


def load_rules():
    with RULES_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data["rules"]


def main():
    rules = load_rules()

    parser = CiscoConfigParser()
    engine = ComplianceEngine()

    for config_path, expected_passes in CONFIGS:

        print("\n" + "=" * 70)
        print(f"CONFIG: {config_path}")
        print("=" * 70)

        config = parser.parse_file(config_path)

        results = engine.evaluate(
            config,
            rules
        )

        passed = sum(
            result["status"] == "PASS"
            for result in results
        )

        failed = sum(
            result["status"] == "FAIL"
            for result in results
        )

        for result in results:
            print(
                f"{result['status']:4} | "
                f"{result['rule_id']:12} | "
                f"{result['title']}"
            )

        print("-" * 70)
        print(f"PASS: {passed}")
        print(f"FAIL: {failed}")
        print(f"TOTAL: {len(results)}")
        print(f"EXPECTED PASS: {expected_passes}")

        assert passed == expected_passes, (
            f"Expected {expected_passes} passes, "
            f"but got {passed}"
        )


if __name__ == "__main__":
    main()