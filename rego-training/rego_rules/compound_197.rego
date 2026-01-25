package compound_197

import rego.v1

# METADATA
# title: Verify all tasks that have a 'rebuild' parameter have it set to 'false'.
# description: >-
#   Verify all tasks that have a 'rebuild' parameter have it set to 'false'.
# custom:
#   short_name: compound_197
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	rebuild := task.invocation.parameters.rebuild
	rebuild
	rebuild == "true"
	result := sprintf("Task %s has rebuild parameter set to true", [task.name])
}
