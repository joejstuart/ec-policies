package task_param_066

import rego.v1

# METADATA
# title: Verify the prefetch-dependencies task has the config-file-content parameter set.
# description: >-
#   Verify the prefetch-dependencies task has the config-file-content parameter set.
# custom:
#   short_name: task_param_066
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "prefetch-dependencies"
	not task.invocation.parameters["config-file-content"]
	result := "prefetch-dependencies task does not have config-file-content parameter"
}
