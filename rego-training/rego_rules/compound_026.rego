package compound_026

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource with a digest.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a configSource with a digest.
# custom:
#   short_name: compound_026
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.configSource.digest
	result := sprintf("Task %s configSource does not have digest", [task.name])
}
