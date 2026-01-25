package task_result_073

import rego.v1

# METADATA
# title: Verify the prefetch-dependencies task produced a result named 'SOURCE_ARTIFACT'.
# description: >-
#   Verify the prefetch-dependencies task produced a result named 'SOURCE_ARTIFACT'.
# custom:
#   short_name: task_result_073
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "prefetch-dependencies"
	not "SOURCE_ARTIFACT" in {r.name | some r in task.results}
	result := "prefetch-dependencies task did not produce SOURCE_ARTIFACT result"
}
