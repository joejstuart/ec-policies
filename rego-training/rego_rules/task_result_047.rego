package task_result_047

import rego.v1

# METADATA
# title: Verify the git-clone task produced a result named 'short-commit'.
# description: >-
#   Verify the git-clone task produced a result named 'short-commit'.
# custom:
#   short_name: task_result_047
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not "short-commit" in {r.name | some r in task.results}
	result := "git-clone task did not produce short-commit result"
}
