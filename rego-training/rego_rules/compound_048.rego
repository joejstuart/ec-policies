package compound_048

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have bundle references that are not empty strings.
# description: >-
#   Verify all tasks in the PipelineRun attestation have bundle references that are not empty strings.
# custom:
#   short_name: compound_048
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	bundle := task.ref.bundle
	bundle == ""
	result := sprintf("Task %s has empty bundle reference", [task.name])
}
