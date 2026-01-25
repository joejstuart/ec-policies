package task_param_067

import rego.v1

# METADATA
# title: Verify the prefetch-dependencies task has the dev-package-managers parameter set.
# description: >-
#   Verify the prefetch-dependencies task has the dev-package-managers parameter set.
# custom:
#   short_name: task_param_067
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "prefetch-dependencies"
	not task.invocation.parameters["dev-package-managers"]
	result := "prefetch-dependencies task does not have dev-package-managers parameter"
}
