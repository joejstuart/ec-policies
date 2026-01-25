package compound_029

import rego.v1

# METADATA
# title: Verify all tasks in the PipelineRun attestation have bundle references that do not use the 'latest' tag.
# description: >-
#   Verify all tasks in the PipelineRun attestation have bundle references that do not use the 'latest' tag.
# custom:
#   short_name: compound_029
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	bundle := task.ref.bundle
	bundle
	contains(bundle, ":latest")
	not contains(bundle, "@sha256:")
	result := sprintf("Task %s bundle %s uses latest tag without digest", [task.name, bundle])
}
