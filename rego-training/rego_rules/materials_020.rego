package materials_020

import rego.v1

# METADATA
# title: Verify all materials in the attestation have a SHA256 digest.
# description: >-
#   Verify all materials in the attestation have a SHA256 digest.
# custom:
#   short_name: materials_020
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	not material.digest.sha256
	result := sprintf("Material %s does not have SHA256 digest", [material.uri])
}
