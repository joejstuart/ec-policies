package compound_070

import rego.v1

# METADATA
# title: Verify all tasks that have a 'log-level' parameter have it set to 'info' or 'debug'.
# description: >-
#   Verify all tasks that have a 'log-level' parameter have it set to 'info' or 'debug'.
# custom:
#   short_name: compound_070
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	log_level := task.invocation.parameters["log-level"]
	log_level
	not log_level in {"info", "debug"}
	result := sprintf("Task %s has invalid log-level: %s", [task.name, log_level])
}
