package compound_056

import rego.v1

# METADATA
# title: Verify all tasks that have an 'image-url' parameter produced an IMAGE_URL result.
# description: >-
#   Verify all tasks that have an 'image-url' parameter produced an IMAGE_URL result.
# custom:
#   short_name: compound_056
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.invocation.parameters["image-url"]
	not "IMAGE_URL" in {r.name | some r in task.results}
	result := sprintf("Task %s has image-url parameter but no IMAGE_URL result", [task.name])
}
