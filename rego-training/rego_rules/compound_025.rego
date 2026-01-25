package compound_025

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource with a uri.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a configSource with a uri.
# custom:
#   short_name: compound_025
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.configSource.uri
	result := sprintf("Task %s configSource does not have uri", [task.name])
}
