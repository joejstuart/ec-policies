package single_key_007

import rego.v1

# METADATA
# title: Verify the build task produced a result named 'IMAGE_URL'.
# description: >-
#   Verify the build task produced a result named 'IMAGE_URL'.
# custom:
#   short_name: single_key_007
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not "IMAGE_URL" in {r.name | some r in task.results}
	result := "Build task did not produce IMAGE_URL result"
}
