package task_param_043

import rego.v1

# METADATA
# title: Verify the git-clone task has the depth parameter set.
# description: >-
#   Verify the git-clone task has the depth parameter set.
# custom:
#   short_name: task_param_043
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not task.invocation.parameters.depth
	result := "git-clone task does not have depth parameter"
}
