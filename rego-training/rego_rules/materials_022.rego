package materials_022

import rego.v1

# METADATA
# title: Verify all materials with SHA1 digest have valid 40-character hex format.
# description: >-
#   Verify all materials with SHA1 digest have valid 40-character hex format.
# custom:
#   short_name: materials_022
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	commit := material.digest.sha1
	commit
	not regex.match(`^[a-f0-9]{40}$`, commit)
	result := sprintf("Material SHA1 digest %s is not valid format", [commit])
}
