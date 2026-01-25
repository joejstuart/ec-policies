package task_result_048

import rego.v1

# METADATA
# title: Verify the git-clone task produced a result named 'commit-timestamp'.
# description: >-
#   Verify the git-clone task produced a result named 'commit-timestamp'.
# custom:
#   short_name: task_result_048
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not "commit-timestamp" in {r.name | some r in task.results}
	result := "git-clone task did not produce commit-timestamp result"
}
