---
name: lint-and-conventions
description: >
  Lint and validate policy conventions. Use when users ask "lint error",
  "regal", "opa fmt", "conventions-check", "annotations wrong", "license header",
  "prefer-parsed-blob", or need help fixing lint/convention failures.
---

# Lint and Convention Checks

## Running All Checks

```bash
make lint              # license headers + regal
make fmt               # opa fmt --write
make conventions-check # annotation validation
make opa-check         # strict mode compile
```

## Regal Linter

Config: `.regal/config.yaml`

```bash
make lint        # runs regal lint policy/
./hack/regal.sh lint policy/   # with EC custom builtins registered
```

### Custom Rule: prefer-parsed-blob

Location: `.regal/rules/custom/prefer_parsed_blob.rego`

Enforces using `oci.parsed_blob(ref)` instead of `json.unmarshal(ec.oci.blob(ref))`.
The only exception is `policy/lib/oci/oci.rego` itself.

### Test File Relaxations

`_test.rego` files have relaxed rules:
- No rule-length or line-length limits
- Pointless-reassignment allowed (common in test setup)

### Global Relaxations

These apply to all `.rego` files (not just tests):
- Unresolved references allowed for `data.rule_data`, `data.config`, `data.trusted_tasks` (since Regal does not scan data files)

## License Headers

Required format:
```
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# ...
# SPDX-License-Identifier: Apache-2.0
```

Fix missing headers:
```bash
make lint-fix
```

## Conventions Check

Validates METADATA annotations via `checks/annotations.rego`:

| Check | What it validates |
|-------|-------------------|
| Required fields | `title`, `description`, `custom.short_name`, `custom.failure_msg` |
| Unique codes | No duplicate `short_name` across rules |
| Valid depends_on | Referenced rules exist and their collections are a superset of the dependent rule's collections |
| Valid effective_on | RFC3339 format when present |

Fix convention errors by updating the rule's METADATA annotation block.

## OPA Strict Check

```bash
make opa-check
```

Runs `opa check --strict` on all policy and test files. Common failures:
- Unused imports
- Deprecated builtins
- Shadowed variables

## Formatting

```bash
make fmt          # format all .rego files
make fmt-amend    # format and amend last commit
make ready        # fmt + amend (convenience)
```

CI runs `make fmt-check` which fails if any file differs from `opa fmt` output.
