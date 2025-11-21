# Test Cases

## 1. Coexistence With trusted_tasks
(R1–R3, R16)

### A1 — On trusted_tasks, no rules → trusted

**Rules:**
```yaml
trusted_tasks:
  oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4:
    - ref: sha256:abc

trusted_task_rules: {}
```

**Evaluation:**
- `now: 2025-01-01Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: false`
- `denied_by_rules: false`
- `is_trusted: true`

### A2 — On trusted_tasks, but expired → untrusted

**Rules:**
```yaml
trusted_tasks:
  oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4:
    - ref: sha256:abc
      expires_on: "2024-12-31T00:00:00Z"

trusted_task_rules: {}
```

**Evaluation:**
- `now: 2025-01-10Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: false`
- `denied_by_rules: false`
- `expired_on_trusted_tasks_list: true`
- `is_trusted: false` (expired)

### A3 — Not on trusted_tasks, no rules → untrusted

**Rules:**
```yaml
trusted_tasks: {}
trusted_task_rules: {}
```

**Evaluation:**
- `task_ref: oci://quay.io/myorg/other/task:1.0@sha256:abc`

**Expected:**
- `allowed_by_rules: false`
- `denied_by_rules: false`
- `is_trusted: false`

## 2. Basic Allow Rules (pattern only)
(R4, R6, R7, R19)

### B1 — Allow by location

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Trust all tekton-catalog
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny: []
trusted_tasks: {}
```

**Evaluation:**
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: false`
- `is_trusted: true`

### B2 — Outside pattern → not trusted

Same rules as B1.

**Evaluation:**
- `task_ref: oci://quay.io/myorg/other/task:1.0`

**Expected:**
- `allowed_by_rules: false`
- `denied_by_rules: false`
- `is_trusted: false`

## 3. Deny Precedence
(R1, R2, R11, R14)

### C1 — On trusted_tasks but denied by rules → untrusted

When `trusted_task_rules` is defined, `trusted_tasks` is ignored. The deny rule from `trusted_task_rules` takes precedence.

**Rules:**
```yaml
trusted_tasks:
  oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4:
    - ref: sha256:abc

trusted_task_rules:
  allow: []
  deny:
    - name: Block buildah 0.4
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      message: "task-buildah:0.4 is deprecated"
      effective_on: 2025-01-01
```

**Evaluation:**
- `now: 2025-01-10Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: false`
- `denied_by_rules: true`
- `is_trusted: false` (deny rule takes precedence; trusted_tasks is ignored because rules are defined)

### C2 — Allowed by pattern but denied → untrusted

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow tekton catalog
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny:
    - name: Expire buildah 0.4
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      message: "Expired"
      effective_on: 2025-01-01
trusted_tasks: {}
```

**Evaluation:**
- `now: 2025-01-10Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: true`
- `is_trusted: false` (deny takes priority over allow per ADR)

## 4. Time-Based Allow Rules
(R9, R15)

### D1 — Allow rule not yet effective / later effective

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Trust tekton starting Feb
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
      effective_on: 2025-02-01
  deny: []
trusted_tasks: {}
```

**Before date:**
- `now: 2025-01-15Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- → `allowed_by_rules: false`
- → `is_trusted: false`

**After date:**
- `now: 2025-02-10Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- → `allowed_by_rules: true`
- → `is_trusted: true`

## 5. Version-Based Deny Rules (Expiry)
(R12, R13, R21)

### E1 — Expire <0.5 starting on date

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow all tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny:
    - name: Expire buildah <0.5
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      versions: ["<0.5"]
      effective_on: 2025-11-15
trusted_tasks: {}
```

**Before effective date (2025-11-10Z):**
- `now: 2025-11-10Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- `allowed_by_rules: true`
- `denied_by_rules: false`
- `is_trusted: true`

**After (2025-11-20Z):**
- `now: 2025-11-20Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- `allowed_by_rules: true`
- `denied_by_rules: true`
- `is_trusted: false`

- `now: 2025-11-20Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.5@sha256:def`
- `allowed_by_rules: true`
- `denied_by_rules: false`
- `is_trusted: true`

### E2 — Two staged version expiries: <0.5 then <0.5.1

Direct ADR example:

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow all tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*

  deny:
    - name: Expire <0.5
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      versions: ["<0.5"]
      effective_on: 2025-11-15

    - name: Expire <0.5.1
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      versions: ["<0.5.1"]
      effective_on: 2025-11-29
trusted_tasks: {}
```

**Timeline expectations:**

- **2025-11-20:**
  - `now: 2025-11-20Z`
  - `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
  - `allowed_by_rules: true`
  - `denied_by_rules: true`
  - `is_trusted: false`
  
  - `now: 2025-11-20Z`
  - `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.5@sha256:def`
  - `allowed_by_rules: true`
  - `denied_by_rules: false`
  - `is_trusted: true`

- **2025-12-01:**
  - `now: 2025-12-01Z`
  - `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.5@sha256:def`
  - `allowed_by_rules: true`
  - `denied_by_rules: true`
  - `is_trusted: false`
  
  - `now: 2025-12-01Z`
  - `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.5.1@sha256:ghi`
  - `allowed_by_rules: true`
  - `denied_by_rules: false`
  - `is_trusted: true`

### E3 — Only expire certain 2.x versions

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow all tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*

  deny:
    - name: Expire older 2.x
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-foo
      versions: [">=2,<2.1.0"]
      effective_on: 2025-10-30
trusted_tasks: {}
```

**Evaluation:**
- `now: 2025-11-01Z`

**Expected:**

- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-foo:1.9.0@sha256:abc`
  - `allowed_by_rules: true`
  - `denied_by_rules: false`
  - `is_trusted: true`

- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-foo:2.0.0@sha256:def`
  - `allowed_by_rules: true`
  - `denied_by_rules: true`
  - `is_trusted: false`

- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-foo:2.1.0@sha256:ghi`
  - `allowed_by_rules: true`
  - `denied_by_rules: false`
  - `is_trusted: true`

## 6. Overlapping Allow Rules (Constraints Stack)
(R10, R20)

Even without signing_key, overlapping allow rules must both be satisfied once effective.
This tests the AND-semantics of overlapping allows.

### F1 — Two overlapping allow rules with staggered effective_on

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Base allow by location
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*

    - name: Additional allow constraint becomes active later
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
      effective_on: 2026-01-01

  deny: []
trusted_tasks: {}
```

**Before 2026:**
- `now: 2025-12-15Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- Only rule #1 applies (rule #2 not yet effective)
- `allowed_by_rules: true`
- `is_trusted: true`

**After 2026:**
- `now: 2026-01-15Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`
- Both rules apply, but rule #2 has no additional criteria beyond pattern matching
- Both rules are satisfied (pattern matches, no other constraints)
- `allowed_by_rules: true`
- `is_trusted: true`
- validates overlapping allow interpretation: all matching allow rules must be satisfied

(Even without signing_key, this test ensures multiple allow rules stack and must all be satisfied according to ADR requirement: "meets the criteria in all matching `allow` rules".)

## 7. Deprecation Deny Rule With Message
(R11)

### G1 — Deny with user-visible message

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny:
    - name: Deprecate manifest
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-build-image-manifest*
      message: >
        This task was renamed to build-image-index.
      effective_on: 2025-10-26
trusted_tasks: {}
```

**Evaluation:**
- `now: 2025-11-01Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-build-image-manifest:1.0@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: true`
- `is_trusted: false`
- message returned in evaluation output

## 8. Rules Take Precedence Over trusted_tasks
(R16)

### H1 — Rules allow, trusted_tasks expiry is ignored

When `trusted_task_rules` is defined, `trusted_tasks` is completely ignored.

**Rules:**
```yaml
trusted_tasks:
  oci://quay.io/.../task-buildah:0.4:
    - ref: sha256:abc
      expires_on: 2025-01-01T00:00:00Z

trusted_task_rules:
  allow:
    - name: Allow tekton catalog
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny: []
```

**Evaluation:**
- `now: 2025-02-01Z`
- `task_ref: oci://quay.io/.../task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: false`
- `is_trusted: true` (trusted_tasks expiry is ignored because rules are defined)

## 9. Non-Semver Tag Edge Case
(R12, R17)

Your implementation must decide how to treat non-semver tags.
Assume: non-semver tags never match version constraints.

### I1 — latest does not match version deny rule

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
  deny:
    - name: Expire <0.5
      pattern: oci://quay.io/konflux-ci/tekton-catalog/task-buildah*
      versions: ["<0.5"]
      effective_on: 2025-11-15
trusted_tasks: {}
```

**Evaluation:**
- `now: 2025-11-20Z`
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:latest@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: false` (non-semver tag "latest" doesn't match version constraint)
- `is_trusted: true`

## 10. Placeholder Future Git Reference Test
(R18)

Not evaluated yet, but ensures schema is flexible.

### J1 — Git reference pattern (skipped / TBD)

```yaml
trusted_task_rules:
  allow:
    - name: Future git trust
      pattern: git+https://github.com/konflux-ci/build-definitions.git//task/buildah/*
  deny: []
```

**Expected:**
- Mark as TODO/not implemented
- Pattern parsing must not crash

## 11. Unknown Fields Ignored (Extensibility)
(R22)

### K1 — Unknown fields ignored

**Rules:**
```yaml
trusted_task_rules:
  allow:
    - name: Allow tekton
      pattern: oci://quay.io/konflux-ci/tekton-catalog/*
      foo: bar   # unknown field
  deny: []
trusted_tasks: {}
```

**Evaluation:**
- `task_ref: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc`

**Expected:**
- `allowed_by_rules: true`
- `denied_by_rules: false`
- `is_trusted: true`
- no evaluation errors (unknown field `foo` is ignored for extensibility)

## Storage Location for trusted_task_rules

The `trusted_task_rules` will be defined in the EC config and called by Conftest/OPA as data, referenced via a git URL. The question is: which git repository should store these rules?

### Option 1: Distributed — Rules in each task repository

Store `trusted_task_rules` in each repository where the tasks live.

**Advantages:**
- Clean separation: automation to keep rules updated can be handled by CI in the same repository
- Co-location: rules are maintained alongside the tasks they govern

**Disadvantages:**
- Trust management: requires full trust of any repository that contains a `trusted_task_rules` list
- Harder to audit: distributed rules make it more difficult to manage what makes it into the trusted rules across all repositories

### Option 2: Centralized — Rules in a single central repository

Store all `trusted_task_rules` in one central repository.

**Advantages:**
- High level of trust: all rules from any repository are stored in one central, controlled location
- Centralized governance: easier to audit and manage all trusted task rules in one place

**Disadvantages:**
- Update overhead: requires a pull request for each update, with CI and approval processes that can take time
- Trust verification: if CI is automated, how do we verify that a trusted actor submitted the pull request? Anyone can make a PR to add a trusted task, requiring manual vetting by whoever merges the PR