package materials_091

import rego.v1

# METADATA
# title: Verify all materials with oci:// URI have SHA256 digest.
# description: >-
#   Verify all materials with oci:// URI have SHA256 digest.
# custom:
#   short_name: materials_091
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	startswith(material.uri, "oci://")
	not material.digest.sha256
	result := sprintf("Material with oci:// URI %s does not have SHA256 digest", [material.uri])
}
