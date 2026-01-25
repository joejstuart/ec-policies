package single_key_004

import rego.v1

# METADATA
# title: Verify the prefetch-dependencies task was not invoked with mode parameter set to 'permissive'.
# description: >-
#   Verify the prefetch-dependencies task was not invoked with mode parameter set to 'permissive'.
# custom:
#   short_name: single_key_004
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "prefetch-dependencies"
	task.invocation.parameters.mode == "permissive"
	result := "prefetch-dependencies mode is permissive"
}
