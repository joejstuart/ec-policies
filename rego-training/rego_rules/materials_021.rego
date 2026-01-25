package materials_021

import rego.v1

# METADATA
# title: Verify all materials with SHA1 digest have a git URI.
# description: >-
#   Verify all materials with SHA1 digest have a git URI.
# custom:
#   short_name: materials_021
#
deny contains result if {
	some attestation in input.attestations
	some material in attestation.statement.predicate.materials
	material.digest.sha1
	not startswith(material.uri, "git+")
	result := sprintf("Material with SHA1 digest has non-git URI: %s", [material.uri])
}
