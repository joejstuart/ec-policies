package compound_003

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a bundle reference with a digest (contains @sha256:).
# description: >-
#   Verify all tasks in the PipelineRun attestation have a bundle reference with a digest (contains @sha256:).
# custom:
#   short_name: compound_003
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	bundle := task.ref.bundle
	bundle
	not contains(bundle, "@sha256:")
	result := sprintf("Task %s uses bundle without digest: %s", [task.name, bundle])
}
