package single_key_016

import rego.v1

# METADATA
# title: Verify the build task reference name matches the task name.
# description: >-
#   Verify the build task reference name matches the task name.
# custom:
#   short_name: single_key_016
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	task.ref.name != "build"
	result := sprintf("Build task reference name %s does not match task name", [task.ref.name])
}
