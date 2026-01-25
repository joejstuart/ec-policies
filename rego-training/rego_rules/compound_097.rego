package compound_097

import rego.v1

# METADATA
# title: Verify all tasks with names ending in '-oci-ta' have bundle references.
# description: >-
#   Verify all tasks with names ending in '-oci-ta' have bundle references.
# custom:
#   short_name: compound_097
#
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	endswith(task.name, "-oci-ta")
	not task.ref.bundle
	result := sprintf("Task %s ending in -oci-ta does not have bundle reference", [task.name])
}
