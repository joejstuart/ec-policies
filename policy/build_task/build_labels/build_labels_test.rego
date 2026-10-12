package build_labels_test

import rego.v1

import data.build_labels
import data.lib.assertions

test_build_label_found if {
	# regal ignore:line-length
	assertions.assert_empty(build_labels.deny) with input as {"metadata": {"labels": {"build.appstudio.redhat.com/build_type": "docker"}}}
}

test_build_label_not_found if {
	# A proper object missing the label trips both the legacy rule and its v2 successor.
	assertions.assert_equal_results(build_labels.deny, {
		{
			"code": "build_labels.build_type_label_set",
			"msg": "The required build label 'build.appstudio.redhat.com/build_type' is missing",
		},
		{
			"code": "build_labels.build_type_label_set_v2",
			"msg": "The required build label 'build.appstudio.redhat.com/build_type' is missing",
		},
	}) with input as {"metadata": {"labels": {"bad": "docker"}}}
}

test_no_labels if {
	assertions.assert_equal_results(build_labels.deny, {{
		"code": "build_labels.build_task_has_label",
		"msg": "The task definition does not include any labels",
	}}) with input as {"metadata": {"name": "no_labels"}}
}

# A defined but non-object metadata.labels is caught by the v2 rule only; the
# legacy build_type_label_set silently passes it (the gap v2 closes), and
# build_task_has_label does not fire because labels is present (just malformed).
test_malformed_labels if {
	expected := {{
		"code": "build_labels.build_type_label_set_v2",
		"msg": "The required build label 'build.appstudio.redhat.com/build_type' is missing",
	}}
	assertions.assert_equal_results(build_labels.deny, expected) with input as {"metadata": {"labels": null}}
	assertions.assert_equal_results(build_labels.deny, expected) with input as {"metadata": {"labels": ["build.appstudio.redhat.com/build_type"]}}
	assertions.assert_equal_results(build_labels.deny, expected) with input as {"metadata": {"labels": "build.appstudio.redhat.com/build_type"}}
	assertions.assert_equal_results(build_labels.deny, expected) with input as {"metadata": {"labels": 1}}
}
