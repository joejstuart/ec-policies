package single_key_015

import rego.v1

# METADATA
# title: Verify the build task reference has kind 'Task'.
# description: >-
#   Verify the build task reference has kind 'Task'.
# custom:
#   short_name: single_key_015
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	task.ref.kind != "Task"
	result := sprintf("Build task reference kind is %s, expected Task", [task.ref.kind])
}
