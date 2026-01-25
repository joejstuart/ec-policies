package compound_001

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation completed successfully.
# description: >-
#   Verify all tasks in the PipelineRun attestation completed successfully.
# custom:
#   short_name: compound_001
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.status != "Succeeded"
	result := sprintf("Task %s did not succeed", [task.name])
}
