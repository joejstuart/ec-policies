package task_023

import rego.v1

# METADATA
# title: Verify the build task configSource has an entryPoint.
# description: >-
#   Verify the build task configSource has an entryPoint.
# custom:
#   short_name: task_023
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.configSource.entryPoint
	result := "Build task configSource does not have entryPoint"
}
