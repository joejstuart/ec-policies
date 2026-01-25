package subject_204

import rego.v1

# METADATA
# title: Verify all subject images have SHA256 digests in valid 64-character hex format.
# description: >-
#   Verify all subject images have SHA256 digests in valid 64-character hex format.
# custom:
#   short_name: subject_204
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	sha256 := subject.digest.sha256
	sha256
	not regex.match(`^[a-f0-9]{64}$`, sha256)
	result := sprintf("Subject image %s has invalid SHA256 digest format", [subject.name])
}
