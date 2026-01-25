package materials_202

import rego.v1

# METADATA
# title: Verify all materials with SHA1 digest have valid 40-character hex format.
# description: >-
#   Verify all materials with SHA1 digest have valid 40-character hex format.
# custom:
#   short_name: materials_202
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	sha1 := material.digest.sha1
	sha1
	not regex.match(`^[a-f0-9]{40}$`, sha1)
	result := sprintf("Material SHA1 digest %s is not valid format", [sha1])
}
