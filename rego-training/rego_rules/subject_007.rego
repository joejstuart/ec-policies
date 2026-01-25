package subject_007

import rego.v1

# METADATA
# title: Verify the attestation has a subject image with name containing 'quay.io'.
# description: >-
#   Verify the attestation has a subject image with name containing 'quay.io'.
# custom:
#   short_name: subject_007
#
deny contains result if {
	some attestation in input.attestations
	subject_names := {s.name | some s in attestation.statement.subject}
	not count({name | some name in subject_names; contains(name, "quay.io")}) > 0
	result := "No subject image contains quay.io"
}
