---
name: run-and-debug
description: >
  Run and debug policy evaluation locally. Use when users ask "run locally",
  "debug policy", "fetch attestation", "check-release", "coverage gaps",
  "EC_REF", "ec-opa", or need help evaluating policies against real data.
---

# Run and Debug Policies Locally

## Quick Local Evaluation

```bash
make fetch-att                          # fetch attestation from golden image
make fetch-att IMAGE=<ref> KEY=<path>   # custom image with custom key
make dummy-config                       # generate minimal policy config
make check-release                      # evaluate release policies against fetched input
```

## Fetching Pipeline Definitions

```bash
make fetch-pipeline                                    # default pipeline
make fetch-pipeline PIPELINE=quay.io/konflux-ci/...    # specific pipeline bundle
make check-pipeline                                    # evaluate pipeline policies
```

## Testing Against a Specific CLI Version

```bash
EC_REF=main make quiet-test           # test with latest CLI from main
EC_REF=release-v0.2 make quiet-test   # test with specific release
```

## Coverage Gaps

```bash
make coverage    # shows uncovered lines without failing
```

100% coverage is mandatory. Fix gaps before submitting.

## IDE Integration

```bash
make ide-binaries    # builds bin/ec and bin/regal for IDE use
./hack/ec-opa.sh eval 'data.my_rule.deny' -d policy -d example/data -i input/input.json
```

## Network Isolation

Tests run under `unshare -r -n` (no network) when available. If tests fail with network errors locally, you may need to allow unprivileged user namespaces (note: this weakens AppArmor restrictions):

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Debugging a Specific Rule

1. Fetch real input: `make fetch-att IMAGE=<failing-image> KEY=<path>`
2. Evaluate just your rule:
   ```bash
   ./hack/ec-opa.sh eval 'data.my_rule.deny' \
     -d policy -d example/data -i input/input.json
   ```
3. Add `print()` statements in your rule for tracing
4. Check rule data: `./hack/ec-opa.sh eval 'data.rule_data.my_key' -d example/data`

## Acceptance Tests

```bash
make acceptance    # runs Go+Godog Cucumber scenarios
```

Acceptance tests validate end-to-end policy evaluation with pre-recorded JSON inputs
in `acceptance/samples/`. No containers or kind cluster needed.

Refresh sample data from live images:
```bash
./hack/refresh-examples.sh
```

## Continuous Testing

```bash
make watch                       # re-runs on file change (requires entr)
make TEST="my_rule" watch        # filtered watch
make live-test                   # entr-based alternative
```
