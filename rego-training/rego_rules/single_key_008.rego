package single_key_008

import rego.v1

# METADATA
# title: Verify the build task produced a result named 'IMAGE_DIGEST'.
# description: >-
#   Verify the build task produced a result named 'IMAGE_DIGEST'.
# custom:
#   short_name: single_key_008
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not "IMAGE_DIGEST" in {r.name | some r in task.results}
	result := "Build task did not produce IMAGE_DIGEST result"
}
