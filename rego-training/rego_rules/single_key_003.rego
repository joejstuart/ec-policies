package single_key_003

import rego.v1

# METADATA
# title: Verify the git-clone task was invoked with sslVerify parameter set to 'true'.
# description: >-
#   Verify the git-clone task was invoked with sslVerify parameter set to 'true'.
# custom:
#   short_name: single_key_003
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "git-clone"
	task.invocation.parameters.sslVerify != "true"
	result := "git-clone task sslVerify parameter is not true"
}
