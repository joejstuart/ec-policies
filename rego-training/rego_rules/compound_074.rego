package compound_074

import rego.v1

# METADATA
# title: Verify all tasks that have results have at least one result with a non-empty value.
# description: >-
#   Verify all tasks that have results have at least one result with a non-empty value.
# custom:
#   short_name: compound_074
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	count(task.results) > 0
	all_empty := {r.name | some r in task.results; r.value == ""}
	count(all_empty) == count(task.results)
	result := sprintf("Task %s has all empty results", [task.name])
}
