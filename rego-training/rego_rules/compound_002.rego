package compound_002

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a bundle reference.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a bundle reference.
# custom:
#   short_name: compound_002
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.ref.bundle
	result := sprintf("Task %s does not have a bundle reference", [task.name])
}
