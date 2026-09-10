class ComplianceEngine:
    """
    Generic, data-driven compliance engine.

    The engine does not contain any rule-specific logic.
    All compliance requirements come from the rule definition JSON.
    """

    def evaluate(self, config, rules):
        """
        Evaluate all rules against a canonical configuration.

        Args:
            config (dict): Canonical configuration produced by a parser.
            rules (list): Declarative compliance rules.

        Returns:
            list: Compliance results.
        """

        results = []

        for rule in rules:
            result = self._evaluate_rule(config, rule)
            results.append(result)

        return results

    def _evaluate_rule(self, config, rule):
        """
        Evaluate one declarative rule.
        """

        target_path = rule["target"]["path"]
        condition = rule["condition"]

        actual_values = self._get_values(
            config,
            target_path
        )

        passed = self._evaluate_condition(
            actual_values,
            condition
        )

        return {
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "status": "PASS" if passed else "FAIL",
            "expected": condition.get("expected"),
            "actual": actual_values
        }

    def _get_values(self, data, path):
        """
        Retrieve values from a nested dictionary/list using
        dot notation and [*] wildcards.

        Example:

            management.ssh.timeout

        or:

            management.vty[*].transport
        """

        parts = path.split(".")

        values = [data]

        for part in parts:

            next_values = []

            if part.endswith("[*]"):

                key = part[:-3]

                for value in values:

                    if not isinstance(value, dict):
                        continue

                    collection = value.get(key, [])

                    if isinstance(collection, list):
                        next_values.extend(collection)

            else:

                for value in values:

                    if not isinstance(value, dict):
                        continue

                    if part in value:
                        next_values.append(value[part])

            values = next_values

        return values

    def _evaluate_condition(self, values, condition):
        """
        Apply a generic declarative condition.
        """

        operator = condition["operator"]
        expected = condition.get("expected")

        if operator == "exists":
            return any(
                value is not None
                for value in values
            )

        if operator == "equals":
            return any(
                value == expected
                for value in values
            )

        if operator == "contains":
            return any(
                isinstance(value, list)
                and expected in value
                for value in values
            )

        if operator == "all_equals":
            return (
                len(values) > 0
                and all(value == expected for value in values)
            )

        if operator == "less_than_or_equal":
            return any(
                value is not None
                and value <= expected
                for value in values
            )

        if operator == "greater_than_or_equal":
            return any(
                value is not None
                and value >= expected
                for value in values
            )

        raise ValueError(
            f"Unsupported compliance operator: {operator}"
        )