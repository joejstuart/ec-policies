package edge_064

import rego.v1

# METADATA
# title: Verify no two tasks in the PipelineRun attestation have the same name.
# description: >-
#   Verify no two tasks in the PipelineRun attestation have the same name.
# custom:
#   short_name: edge_064
#
deny contains result if {
	some attestation in input.attestations
	task_names := {task.name | some task in attestation.statement.predicate.buildConfig.tasks}
	all_task_names := [task.name | some task in attestation.statement.predicate.buildConfig.tasks]
	count(task_names) != count(all_task_names)
	result := "Tasks have duplicate names"
}
