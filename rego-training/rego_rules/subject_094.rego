package subject_094

import rego.v1

# METADATA
# title: Verify all subject images have SHA256 digests in valid format.
# description: >-
#   Verify all subject images have SHA256 digests in valid format.
# custom:
#   short_name: subject_094
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	digest := subject.digest.sha256
	digest
	not regex.match(`^[a-f0-9]{64}$`, digest)
	result := sprintf("Subject image %s has invalid SHA256 digest format", [subject.name])
}
