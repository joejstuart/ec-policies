---
name: pr-checklist
description: >
  Definition of done for conforma/policy pull requests. Use when users ask
  "is this PR ready", "definition of done", "PR checklist", "before merging",
  "review checklist", or when preparing a PR for review.
---

# PR Definition of Done for conforma/policy

## Before Submitting

- [ ] `make ci` passes locally
- [ ] 100% test coverage on all changed `.rego` files
- [ ] `make fmt` applied (no formatting diff)
- [ ] `make generate-docs` run and output committed (if annotations changed)
- [ ] New deny/warn rules have `effective_on` date set 2-4 weeks in the future
- [ ] New rules added to appropriate `custom.collections`
- [ ] `custom.depends_on` set if the rule requires another rule to pass first

## What `make ci` Runs

This runs, in order:
1. `quiet-test` — OPA tests with 100% coverage gate
2. `acceptance` — Godog integration scenarios
3. `opa-check` — strict mode compilation
4. `conventions-check` — annotation validation
5. `fmt-check` — formatting diff
6. `lint` — license headers + regal
7. `regal-test` — tests for custom regal lint rules
8. `generate-docs`

Note: CI also runs a separate `git diff` step after `make ci` to catch uncommitted generated files.

## Commit Messages

Conventional commits encouraged:
```
feat(EC-1234): add SBOM completeness check for CycloneDX
fix(EC-5678): handle missing predicate in SLSA v1.0 attestation
```

## Common Mistakes

- Forgetting `make generate-docs` after changing METADATA annotations
- Missing `effective_on` on new deny rules (enforces immediately without migration window)
- Not testing both SLSA v0.2 and v1.0 attestation formats
- Adding a rule without `custom.collections` (rule won't be evaluated by any collection)
- Rule data keys without defaults in `policy/lib/rule_data/rule_data.rego`
- Placing `custom.*` annotations at package level instead of rule level

## After Submitting

- CI runs `.github/workflows/pre-merge-ci.yaml` automatically
- PR size labels are applied automatically
- Auto-merge triggers after approval
