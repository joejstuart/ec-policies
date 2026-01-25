package subject_005

import rego.v1

# METADATA
# title: Verify all subject images in the attestation have a digest.
# description: >-
#   Verify all subject images in the attestation have a digest.
# custom:
#   short_name: subject_005
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	not subject.digest
	result := sprintf("Subject image %s does not have a digest", [subject.name])
}
