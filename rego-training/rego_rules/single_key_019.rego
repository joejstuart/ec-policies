package single_key_019

import rego.v1

# METADATA
# title: Verify the git-clone task has the url parameter set.
# description: >-
#   Verify the git-clone task has the url parameter set.
# custom:
#   short_name: single_key_019
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	not task.invocation.parameters.url
	result := "git-clone task does not have url parameter"
}
