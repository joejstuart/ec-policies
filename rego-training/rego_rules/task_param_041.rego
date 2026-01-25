package task_param_041

import rego.v1

# METADATA
# title: Verify the git-clone task has the revision parameter set.
# description: >-
#   Verify the git-clone task has the revision parameter set.
# custom:
#   short_name: task_param_041
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not task.invocation.parameters.revision
	result := "git-clone task does not have revision parameter"
}
