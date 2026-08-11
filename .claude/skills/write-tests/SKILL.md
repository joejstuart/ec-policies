---
name: write-tests
description: >
  Write Rego unit tests for conforma/policy. Use when users ask "add a test",
  "write a test", "test pattern", "assertions", "how to test a rule",
  "tekton_test", "SLSA attestation test", or need help with test conventions.
---

# Write Rego Unit Tests

## File Conventions

- Test file alongside source: `my_rule.rego` -> `my_rule_test.rego`
- Package: `<rule_name>_test` (flat name, e.g. `package labels_test`)
- Test rule naming: `test_<description> if { ... }`
- 100% coverage is mandatory

## Assertions Library

Import: `import data.lib.assertions`

| Function | Use for |
|----------|---------|
| `assertions.assert_empty(set)` | Verify no violations (deny/warn is empty) |
| `assertions.assert_not_empty(set)` | Verify violations exist |
| `assertions.assert_equal(left, right)` | Equality (avoid for booleans) |
| `assertions.assert_not_equal(left, right)` | Inequality |
| `assertions.assert_equal_results(left, right)` | Compare result sets; ignores `collections` and `effective_on` |

## Tekton Test Helpers

Import: `import data.lib.tekton_test`

Build SLSA v1.0 attestations:

```rego
task := tekton_test.slsav1_task("my-task-name")
task_with_results := tekton_test.with_results(task, [
    {"name": "SOME_RESULT", "value": "some-value"},
    {"name": "ANOTHER_RESULT", "value": "another-value"},
])
attestation := tekton_test.slsav1_attestation([task_with_results])
```

## Standard Test Pattern

```rego
package my_rule_test

import rego.v1

import data.lib.assertions
import data.lib.tekton_test
import data.my_rule

test_good_case if {
    task := tekton_test.slsav1_task("my-task")
    task_with_results := tekton_test.with_results(task, [
        {"name": "EXPECTED_RESULT", "value": "good-value"},
    ])
    attestation := tekton_test.slsav1_attestation([task_with_results])
    assertions.assert_empty(my_rule.deny) with input.attestations as [attestation]
}

test_bad_case if {
    task := tekton_test.slsav1_task("my-task")
    task_with_results := tekton_test.with_results(task, [
        {"name": "EXPECTED_RESULT", "value": "bad-value"},
    ])
    attestation := tekton_test.slsav1_attestation([task_with_results])
    assertions.assert_not_empty(my_rule.deny) with input.attestations as [attestation]
}
```

## `with` Overrides

Override input, rule data, or config inline:

```rego
test_custom_rule_data if {
    assertions.assert_empty(my_rule.deny) with input.attestations as [att]
        with data.rule_data.my_key as ["allowed-value"]
}
```

## Running Tests

```bash
make TEST="my_rule" test        # filter by regex
make coverage                   # see uncovered lines
go run github.com/conforma/cli opa test ./policy ./example/data/rule_data.yml ./checks -r "test_good_case"
```
