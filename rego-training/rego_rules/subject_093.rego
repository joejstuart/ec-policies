package subject_093

import rego.v1

# METADATA
# title: Verify all subject images have names that contain a registry.
# description: >-
#   Verify all subject images have names that contain a registry.
# custom:
#   short_name: subject_093
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	name := subject.name
	name
	not contains(name, ".")
	not contains(name, "/")
	result := sprintf("Subject image name %s does not appear to be a valid image reference", [name])
}
