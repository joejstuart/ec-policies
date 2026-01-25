package configsource_208

import rego.v1

# METADATA
# title: Verify all tasks have configSource digest with sha256 that is not empty.
# description: >-
#   Verify all tasks have configSource digest with sha256 that is not empty.
# custom:
#   short_name: configSource_208
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	digest := task.invocation.configSource.digest
	digest
	digest.sha256 == ""
	result := sprintf("Task %s configSource digest has empty sha256", [task.name])
}
