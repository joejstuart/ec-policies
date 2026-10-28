package basic_test

import rego.v1

import data.lib.assertions

import data.basic

test_unexpected_kind if {
	# Both the legacy rule and its v2 successor reject an unexpected kind.
	assertions.assert_equal_results(basic.deny, {
		{
			"code": "basic.expected_kind",
			"msg": "Unexpected kind 'Foo' for pipeline definition",
		},
		{
			"code": "basic.expected_kind_v2",
			"msg": "Unexpected kind 'Foo' for pipeline definition",
		},
	}) with input.kind as "Foo"
}

test_expected_kind if {
	assertions.assert_empty(basic.deny) with input as {
		"apiVersion": "tekton.dev/v1",
		"kind": "Pipeline",
		"spec": {"tasks": []},
	}
}

# A Pipeline-shaped input with the `kind` key entirely removed is rejected by the
# v2 rule only; the legacy `expected_kind` rule stays unchanged (it silently
# passes a missing kind, which is the gap v2 closes).
test_missing_kind if {
	assertions.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind_v2",
		"msg": "Unexpected kind '' for pipeline definition",
	}}) with input as {
		"apiVersion": "tekton.dev/v1",
		"spec": {"tasks": []},
	}
}

# A document that is not an object at all bypasses every other pipeline rule; the
# input_format rule rejects it.
test_input_format if {
	expected := {{
		"code": "basic.input_format",
		"msg": "Pipeline definition must be a JSON/YAML object",
	}}
	assertions.assert_equal_results(basic.deny, expected) with input as "not-an-object"
	assertions.assert_equal_results(basic.deny, expected) with input as ["not", "an", "object"]
}
