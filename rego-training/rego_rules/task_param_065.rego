package task_param_065

import rego.v1

# METADATA
# title: Verify the prefetch-dependencies task has the log-level parameter set.
# description: >-
#   Verify the prefetch-dependencies task has the log-level parameter set.
# custom:
#   short_name: task_param_065
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "prefetch-dependencies"
	not task.invocation.parameters["log-level"]
	result := "prefetch-dependencies task does not have log-level parameter"
}
