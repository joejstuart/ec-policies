package materials_203

import rego.v1

# METADATA
# title: Verify all materials with SHA256 digest have valid 64-character hex format.
# description: >-
#   Verify all materials with SHA256 digest have valid 64-character hex format.
# custom:
#   short_name: materials_203
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	sha256 := material.digest.sha256
	sha256
	not regex.match(`^[a-f0-9]{64}$`, sha256)
	result := sprintf("Material SHA256 digest %s is not valid format", [sha256])
}
