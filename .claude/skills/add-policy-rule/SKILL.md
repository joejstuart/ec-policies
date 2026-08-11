---
name: add-policy-rule
description: >
  Add a new policy rule to conforma/policy. Use when users ask "add a rule",
  "new deny rule", "new policy", "create a check", "effective_on", "collections",
  "METADATA annotations", or need the full workflow for adding a policy rule.
---

# Add a New Policy Rule

## Step 1: Create the Rule

Create `policy/<kind>/<rule_name>/<rule_name>.rego` where kind is one of:
`release`, `pipeline`, `task`, `build_task`, `stepaction`

The structure is: package-level METADATA (title, description), then package declaration
and imports, then rule-level METADATA (custom fields) immediately before each deny/warn rule.

```rego
# METADATA
# title: My rule title
# description: >-
#   Explanation of what this rule checks and why.
package my_rule

import rego.v1

import data.lib
import data.lib.metadata

# METADATA
# custom:
#   short_name: my_short_name
#   failure_msg: "Description of what failed: %s"
#   solution: >-
#     How to fix the violation.
#   collections:
#     - redhat
#     - minimal
#   depends_on:
#     - attestation_type.known_attestation_type
#   effective_on: "2026-09-01T00:00:00Z"
deny contains result if {
    some_value := input.attestations[_].statement.predicate.some_field
    result := metadata.result_helper(rego.metadata.chain(), [some_value])
}
```

## Step 2: Annotations Checklist

Package-level annotations (before `package` declaration):
- `title` — human-readable rule name
- `description` — what it checks and why

Rule-level annotations (before each `deny`/`warn` rule):
- `custom.short_name` — unique identifier (used in exceptions)
- `custom.failure_msg` — printf-style message with `%s` placeholders matching result_helper args
- `custom.collections` — which collections include this rule
- `custom.effective_on` — RFC3339 date; **required** for new deny rules (see Step 5)

Optional:
- `custom.solution` — remediation guidance
- `custom.depends_on` — rules that must pass first (list of `package.short_name`)

## Step 3: Write Tests

Create `policy/<kind>/<rule_name>/<rule_name>_test.rego` with 100% coverage.
See the `write-tests` skill for patterns.

## Step 4: Add to Collections

Membership is declared in the rule's `custom.collections` annotation (not in collection package files).

Available collections: `minimal`, `slsa3`, `redhat`, `redhat_security`, `redhat_rpms`,
`redhat_maven`, `rhtap-multi-ci`, `rhtap-github`, `rhtap-gitlab`, `rhtap-jenkins`,
`github`, `policy_data`, `production`

## Step 5: Set effective_on

New deny rules MUST include `effective_on` with a future date (typically 2-4 weeks out)
to provide a migration window. Without it, the rule enforces immediately on deployment.

## Step 6: Generate Docs

```bash
make generate-docs
git add antora/
```

CI will fail if generated docs are not committed.

## Step 7: Validate

```bash
make ci    # runs tests + opa-check + conventions-check + lint + regal-test + docs
```

`conventions-check` validates all required annotations are present, unique rule codes,
valid `depends_on` references, and correct `effective_on` format.
