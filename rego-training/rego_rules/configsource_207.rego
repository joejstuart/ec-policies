package configsource_207

import rego.v1

# METADATA
# title: Verify all tasks have configSource with entryPoint that is not empty when set.
# description: >-
#   Verify all tasks have configSource with entryPoint that is not empty when set.
# custom:
#   short_name: configSource_207
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	entry_point := task.invocation.configSource.entryPoint
	entry_point
	entry_point == ""
	result := sprintf("Task %s configSource has empty entryPoint", [task.name])
}
