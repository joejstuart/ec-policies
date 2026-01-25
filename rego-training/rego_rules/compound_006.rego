package compound_006

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a reference.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a reference.
# custom:
#   short_name: compound_006
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.ref
	result := sprintf("Task %s does not have a reference", [task.name])
}
