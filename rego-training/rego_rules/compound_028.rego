package compound_028

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have bundle references from quay.io.
# description: >-
#   Verify all tasks in the PipelineRun attestation have bundle references from quay.io.
# custom:
#   short_name: compound_028
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	bundle := task.ref.bundle
	bundle
	not contains(bundle, "quay.io")
	result := sprintf("Task %s bundle %s is not from quay.io", [task.name, bundle])
}
