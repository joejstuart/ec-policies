# Release Policy Diff: konflux → latest

Rules added when deploying `quay.io/conforma/release-policy:konflux` → `quay.io/conforma/release-policy:latest`.

---

## 1. `package_registry_proxy_enabled`

- **Effective:** 2026-06-01
- **Collections:** redhat
- **File:** `policy/release/prefetch_dependencies/prefetch_dependencies.rego`

Triggers if your `prefetch-dependencies` or `prefetch-dependencies-oci-ta` task does not have `enable-package-registry-proxy` set to `"true"`.

Example PipelineRun attestation task result that would trigger this:

```yaml
# This triggers it — param is missing or not "true"
- name: prefetch-dependencies
  params:
    - name: input
      value: some-input
    # no enable-package-registry-proxy param at all
```

To pass:

```yaml
- name: prefetch-dependencies
  params:
    - name: enable-package-registry-proxy
      value: "true"
```

---

## 2. `policy_data_missing`

- **Effective:** now
- **Collections:** redhat_maven, policy_data
- **File:** `policy/release/maven_repos/maven_repos.rego`

Triggers if `allowed_maven_repositories` is missing, empty, or not a list in your rule data.

```yaml
# Triggers — no maven repos defined
rule_data: {}

# Also triggers — empty list
rule_data:
  allowed_maven_repositories: []
```

To pass:

```yaml
rule_data:
  allowed_maven_repositories:
    - "https://repo.maven.apache.org/maven2/"
    - "https://maven.repository.redhat.com/ga/"
```

---

## 3. `deny_unpermitted_urls`

- **Effective:** 2026-05-10 (already active)
- **Collections:** redhat_maven
- **File:** `policy/release/maven_repos/maven_repos.rego`

Triggers for any Maven SBOM package whose repository URL isn't in the allowed list. Packages with no URL are assumed to be from Maven Central.

Example CycloneDX component that would trigger this:

```json
{
  "purl": "pkg:maven/org.example/my-lib@1.0.0",
  "properties": [
    {
      "name": "cdx:maven:repository:url",
      "value": "https://some-internal-repo.example.com/maven/"
    }
  ]
}
```

This fails if `https://some-internal-repo.example.com/maven/` is not in `allowed_maven_repositories`.

A package with no repository URL at all:

```json
{
  "purl": "pkg:maven/org.example/my-lib@1.0.0"
}
```

This is treated as coming from `https://repo.maven.apache.org/maven2/` — which also needs to be in the allowed list.

---

## 4. `allowed_proxy_urls` (CycloneDX)

- **Effective:** 2026-06-01
- **Collections:** redhat, redhat_rpms, policy_data
- **File:** `policy/release/sbom_cyclonedx/sbom_cyclonedx.rego`

Triggers for Hermeto-found components with a proxy-enabled PURL type that are registry dependencies, where the distribution URL doesn't match any allowed pattern.

```json
{
  "purl": "pkg:maven/org.example/my-lib@1.0.0",
  "properties": [
    { "name": "cdx:hermeto:found_by", "value": "hermeto-java" }
  ],
  "externalReferences": [
    {
      "type": "distribution",
      "url": "https://unknown-proxy.example.com/maven/org/example/my-lib/1.0.0/my-lib-1.0.0.jar"
    }
  ]
}
```

With this rule data:

```yaml
proxy_enabled_purl_types: ["maven"]
allowed_proxy_url_patterns:
  maven:
    - "^https://proxy\\.trusted\\.com/maven/.*"
```

The URL `https://unknown-proxy.example.com/...` doesn't match the pattern, so it's denied.

Note: if the PURL had a `download_url` or `vcs_url` qualifier (e.g. `pkg:maven/org.example/my-lib@1.0.0?download_url=...`) it would be skipped — the rule only targets registry dependencies. Components with URL `"NOASSERTION"` are also skipped.

---

## 5. `proxy_metadata_required` (CycloneDX)

- **Effective:** 2026-06-01
- **Collections:** redhat, redhat_rpms, policy_data
- **File:** `policy/release/sbom_cyclonedx/sbom_cyclonedx.rego`

Same scope as #4 but triggers when there's no distribution reference at all:

```json
{
  "purl": "pkg:maven/org.example/my-lib@1.0.0",
  "properties": [
    { "name": "cdx:hermeto:found_by", "value": "hermeto-java" }
  ],
  "externalReferences": []
}
```

No `"distribution"` entry exists, so proxy metadata is missing. Would also trigger if `externalReferences` is omitted entirely.

---

## 6. `allowed_proxy_urls` (SPDX)

- **Effective:** 2026-06-01
- **Collections:** redhat, redhat_rpms, policy_data
- **File:** `policy/release/sbom_spdx/sbom_spdx.rego`

Same logic as #4 but checks `downloadLocation` instead of distribution references:

```json
{
  "name": "my-lib",
  "downloadLocation": "https://unknown-proxy.example.com/maven/org/example/my-lib/1.0.0/my-lib-1.0.0.jar",
  "sourceInfo": "hermeto",
  "externalRefs": [
    {
      "referenceType": "purl",
      "referenceLocator": "pkg:maven/org.example/my-lib@1.0.0"
    }
  ]
}
```

The `downloadLocation` doesn't match any pattern in `allowed_proxy_url_patterns["maven"]`, so it's denied. Packages with `downloadLocation: "NOASSERTION"` are skipped.

---

## 7. `proxy_metadata_required` (SPDX)

- **Effective:** 2026-06-01
- **Collections:** redhat, redhat_rpms, policy_data
- **File:** `policy/release/sbom_spdx/sbom_spdx.rego`

Triggers when `sourceInfo` is empty or missing for a Hermeto-found registry dependency:

```json
{
  "name": "my-lib",
  "downloadLocation": "https://proxy.trusted.com/maven/...",
  "sourceInfo": "",
  "externalRefs": [
    {
      "referenceType": "purl",
      "referenceLocator": "pkg:maven/org.example/my-lib@1.0.0"
    }
  ]
}
```

`sourceInfo` is `""`, so proxy metadata is considered missing. Same result if the field is omitted entirely.

---

## Rule removed

**`proxy_rule_data_format`** (deny) in `hermetic_task` — validates the format of `proxy_enabled_purl_types` and `allowed_proxy_url_patterns` rule data. This rule is present in `konflux` but removed in `latest`.
