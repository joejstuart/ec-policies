package compound_057

import rego.v1

# METADATA
# title: Verify all tasks have both annotations and labels.
# description: >-
#   Verify all tasks have both annotations and labels.
# custom:
#   short_name: compound_057
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.environment.annotations
	not task.invocation.environment.labels
	result := sprintf("Task %s is missing annotations or labels", [task.name])
}
