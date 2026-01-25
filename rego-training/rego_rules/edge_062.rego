package edge_062

import rego.v1

# METADATA
# title: Verify all subject images have names that are not empty.
# description: >-
#   Verify all subject images have names that are not empty.
# custom:
#   short_name: edge_062
#
deny contains result if {
	some attestation in input.attestations
	some subject in attestation.statement.subject
	subject.name == ""
	result := "Subject image has empty name"
}
