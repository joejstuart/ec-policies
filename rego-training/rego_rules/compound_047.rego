package compound_047

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have unique names.
# description: >-
#   Verify all tasks in the PipelineRun attestation have unique names.
# custom:
#   short_name: compound_047
#
deny contains result if {
	some attestation in input.attestations
	task_names := {task.name | some task in attestation.statement.predicate.buildConfig.tasks}
	all_task_names := [task.name | some task in attestation.statement.predicate.buildConfig.tasks]
	count(task_names) != count(all_task_names)
	result := "Tasks have duplicate names"
}
