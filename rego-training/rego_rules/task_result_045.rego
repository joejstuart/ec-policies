package task_result_045

import rego.v1

# METADATA
# title: Verify the git-clone task produced a result named 'commit'.
# description: >-
#   Verify the git-clone task produced a result named 'commit'.
# custom:
#   short_name: task_result_045
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not "commit" in {r.name | some r in task.results}
	result := "git-clone task did not produce commit result"
}
