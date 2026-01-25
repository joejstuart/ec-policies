package configsource_206

import rego.v1

# METADATA
# title: Verify all tasks have configSource with uri that is not empty.
# description: >-
#   Verify all tasks have configSource with uri that is not empty.
# custom:
#   short_name: configSource_206
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	uri := task.invocation.configSource.uri
	uri
	uri == ""
	result := sprintf("Task %s configSource has empty uri", [task.name])
}
