package materials_092

import rego.v1

# METADATA
# title: Verify all materials with quay.io URI have SHA256 digest.
# description: >-
#   Verify all materials with quay.io URI have SHA256 digest.
# custom:
#   short_name: materials_092
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	contains(material.uri, "quay.io")
	not material.digest.sha256
	result := sprintf("Material with quay.io URI %s does not have SHA256 digest", [material.uri])
}
