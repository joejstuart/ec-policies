package task_025

import rego.v1

# METADATA
# title: Verify the build task reference has params.
# description: >-
#   Verify the build task reference has params.
# custom:
#   short_name: task_025
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.ref.params
	result := "Build task reference does not have params"
}
