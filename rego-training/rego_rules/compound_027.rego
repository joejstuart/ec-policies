package compound_027

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource digest with sha256.
# description: >-
#   Verify all tasks in the PipelineRun attestation have a configSource digest with sha256.
# custom:
#   short_name: compound_027
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	digest := task.invocation.configSource.digest
	digest
	not digest.sha256
	result := sprintf("Task %s configSource digest does not have sha256", [task.name])
}
