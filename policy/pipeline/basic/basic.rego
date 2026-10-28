#
# METADATA
# title: Pipeline definition sanity checks
# description: >-
#   Policies to confirm the Tekton Pipeline definition has the expected kind.
#
package basic

import rego.v1

import data.lib.metadata

expected_kind := "Pipeline"

# (Not sure if we need this, but I'm using it to test the docs build.)

# METADATA
# title: Pipeline definition has expected kind
# description: >-
#   Confirm that the pipeline definition has the kind "Pipeline".
# custom:
#   short_name: expected_kind
#   failure_msg: Unexpected kind '%s' for pipeline definition
#
deny contains result if {
	expected_kind != input.kind
	result := metadata.result_helper(rego.metadata.chain(), [input.kind])
}

# METADATA
# title: Pipeline definition has expected kind (v2)
# description: >-
#   Confirm that the pipeline definition has the kind "Pipeline".
# custom:
#   short_name: expected_kind_v2
#   failure_msg: Unexpected kind '%s' for pipeline definition
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	kind := object.get(input, "kind", "")
	expected_kind != kind
	result := metadata.result_helper(rego.metadata.chain(), [kind])
}

# METADATA
# title: Pipeline definition is an object
# description: >-
#   Confirm the pipeline definition is a JSON/YAML object.
# custom:
#   short_name: input_format
#   failure_msg: Pipeline definition must be a JSON/YAML object
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	not is_object(input)
	result := metadata.result_helper(rego.metadata.chain(), [])
}
