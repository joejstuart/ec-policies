package subject_006

import rego.v1

# METADATA
# title: Verify all subject images in the attestation have a SHA256 digest.
# description: >-
#   Verify all subject images in the attestation have a SHA256 digest.
# custom:
#   short_name: subject_006
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	not subject.digest.sha256
	result := sprintf("Subject image %s does not have SHA256 digest", [subject.name])
}
