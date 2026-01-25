package compound_198

import rego.v1

# METADATA
# title: Verify all tasks that have a 'skip-checks' parameter have it set to 'false'.
# description: >-
#   Verify all tasks that have a 'skip-checks' parameter have it set to 'false'.
# custom:
#   short_name: compound_198
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	skip_checks := task.invocation.parameters["skip-checks"]
	skip_checks
	skip_checks == "true"
	result := sprintf("Task %s has skip-checks parameter set to true", [task.name])
}
