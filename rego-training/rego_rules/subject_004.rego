package subject_004

import rego.v1

# METADATA
# title: Verify all subject images in the attestation have a name.
# description: >-
#   Verify all subject images in the attestation have a name.
# custom:
#   short_name: subject_004
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	not subject.name
	result := "Subject image does not have a name"
}
