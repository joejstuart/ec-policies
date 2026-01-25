package task_result_072

import rego.v1

# METADATA
# title: Verify the git-clone task produced a result named 'CHAINS-GIT_URL'.
# description: >-
#   Verify the git-clone task produced a result named 'CHAINS-GIT_URL'.
# custom:
#   short_name: task_result_072
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not "CHAINS-GIT_URL" in {r.name | some r in task.results}
	result := "git-clone task did not produce CHAINS-GIT_URL result"
}
