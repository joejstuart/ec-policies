package lib.metadata_test

import rego.v1

import data.lib.assertions
import data.lib.metadata

test_rule_annotations_with_annotations if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"failure_msg": "Test failure message",
		"pipeline_intention": ["build", "test"],
	}}

	chain := [
		{"annotations": rule_annotations, "path": ["data", "test", "deny"]},
		{"annotations": {}, "path": ["ignored", "path"]},
	]

	assertions.assert_equal(rule_annotations, metadata._rule_annotations(chain))
}

test_rule_annotations_empty_annotations if {
	empty_annotations := {}

	chain := [
		{"annotations": empty_annotations, "path": ["data", "test", "deny"]},
		{"annotations": {"some": "other"}, "path": ["ignored", "path"]},
	]

	assertions.assert_equal(empty_annotations, metadata._rule_annotations(chain))
}

test_rule_annotations_only_first_entry if {
	first_rule_annotations := {"custom": {"short_name": "FirstRule"}}
	second_rule_annotations := {"custom": {"short_name": "SecondRule"}}

	chain := [
		{"annotations": first_rule_annotations, "path": ["data", "test", "deny"]},
		{"annotations": second_rule_annotations, "path": ["other", "path"]},
	]

	# Should only return annotations from the first entry
	assertions.assert_equal(first_rule_annotations, metadata._rule_annotations(chain))
}

test_rule_annotations_single_entry_chain if {
	rule_annotations := {"custom": {"short_name": "SingleRule"}}

	chain := [{"annotations": rule_annotations, "path": ["data", "single", "deny"]}]

	assertions.assert_equal(rule_annotations, metadata._rule_annotations(chain))
}

test_pipeline_intention_match_with_matching_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") matches one of the pipeline_intention values
	assertions.assert_equal(true, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
}

test_pipeline_intention_match_with_non_matching_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") doesn't match any of the pipeline_intention values
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
}

test_pipeline_intention_match_with_empty_pipeline_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": [],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When pipeline_intention is an empty list, should return false
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
}

test_pipeline_intention_match_without_pipeline_intention_field if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"failure_msg": "Some failure message",
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When pipeline_intention field is missing, should return false
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
}

test_pipeline_intention_match_without_custom_field if {
	rule_annotations := {"other": {"some_field": "value"}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When custom field is missing, should return false
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
}

test_pipeline_intention_match_with_null_rule_data if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") is null, should return false
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as null
}

test_pipeline_intention_match_with_multiple_matching_intentions if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "production", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") matches one of multiple pipeline_intention values
	assertions.assert_equal(true, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "production"
}

test_pipeline_intention_match_case_sensitivity if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["Build", "Release"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# Case sensitivity should be preserved
	assertions.assert_equal(false, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "release"
	assertions.assert_equal(true, metadata.pipeline_intention_match(chain)) with data.rule_data.pipeline_intention as "Release"
}

test_result_helper if {
	expected_result := {
		"code": "oh.Hey",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": ["data", "oh", "deny"]},
		{"annotations": {}, "path": ["ignored", "ignored"]}, # Actually not needed any more
	]

	assertions.assert_equal(expected_result, metadata.result_helper(chain, ["foo"]))
}

test_result_helper_with_grandfathering if {
	expected_result := {
		"code": "oh.Hey",
		"collections": ["redhat"],
		"effective_on": "2025-02-01T00:00:00Z",
		"msg": "Bad thing foo (build completed before the 2025-01-15T00:00:00Z cutoff; grandfathered until 2025-02-01T00:00:00Z)",
		"severity": "warning",
		"term": "git-clone",
	}
	assertions.assert_equal(
		expected_result,
		metadata.result_with_grandfathering(
			_result_with_effective_on("2024-01-01T00:00:00Z"),
			_attestation_with_finished_on("2025-01-14T23:59:59Z"),
			_grandfathering_rule,
		),
	) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
}

test_result_helper_with_v02_grandfathering if {
	expected := {
		"code": "oh.Hey",
		"collections": ["redhat"],
		"effective_on": "2025-02-01T00:00:00Z",
		"msg": "Bad thing foo (build completed before the 2025-01-15T00:00:00Z cutoff; grandfathered until 2025-02-01T00:00:00Z)",
		"severity": "warning",
		"term": "git-clone",
	}
	assertions.assert_equal(
		expected,
		metadata.result_with_grandfathering(
			_result_with_effective_on("2024-01-01T00:00:00Z"),
			_v02_attestation_with_finished_on("2025-01-14T23:59:59Z"),
			_grandfathering_rule,
		),
	) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
}

test_grandfathering_rejects_builds_at_or_after_cutoff if {
	every finished_on in ["2025-01-15T00:00:00Z", "2025-01-15T00:00:01Z"] {
		result := _result_with_effective_on("2024-01-01T00:00:00Z")
		assertions.assert_equal(
			result,
			metadata.result_with_grandfathering(
				result,
				_attestation_with_finished_on(finished_on),
				_grandfathering_rule,
			),
		) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
	}
}

test_grandfathering_ends_at_absolute_deadline if {
	result := _result_with_effective_on("2024-01-01T00:00:00Z")
	assertions.assert_equal(
		result,
		metadata.result_with_grandfathering(
			result,
			_attestation_with_finished_on("2025-01-14T23:59:59Z"),
			_grandfathering_rule,
		),
	) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-02-01T00:00:00Z")
}

test_grandfathering_preserves_later_result_effective_on if {
	result := _result_with_effective_on("2025-03-01T00:00:00Z")
	assertions.assert_equal(
		result,
		metadata.result_with_grandfathering(
			result,
			_attestation_with_finished_on("2025-01-14T23:59:59Z"),
			_grandfathering_rule,
		),
	) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
}

test_grandfathering_ignores_unusable_inputs if {
	result := _result_with_effective_on("2024-01-01T00:00:00Z")
	attestation := _attestation_with_finished_on("2025-01-14T23:59:59Z")

	# Malformed or unsupported attestations fail closed.
	every unusable_attestation in [
		_attestation_with_finished_on("not-a-timestamp"),
		_unsupported_attestation_with_finished_on("2025-01-14T23:59:59Z"),
	] {
		assertions.assert_equal(
			result,
			metadata.result_with_grandfathering(result, unusable_attestation, _grandfathering_rule),
		) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
	}

	# Missing, malformed, or non-extending rule dates fail closed.
	every unusable_rule in [
		{},
		{"effective_on": "not-a-timestamp", "grandfather_until": "2025-02-01T00:00:00Z"},
		{"effective_on": "2025-01-15T00:00:00Z", "grandfather_until": "not-a-timestamp"},
		{"effective_on": "2025-01-15T00:00:00Z", "grandfather_until": "2025-01-15T00:00:00Z"},
	] {
		assertions.assert_equal(
			result,
			metadata.result_with_grandfathering(result, attestation, unusable_rule),
		) with data.lib.time.effective_current_time_ns as time.parse_rfc3339_ns("2025-01-20T00:00:00Z")
	}
}

_grandfathering_rule := {
	"effective_on": "2025-01-15T00:00:00Z",
	"grandfather_until": "2025-02-01T00:00:00Z",
}

_result_with_effective_on(effective_on) := {
	"code": "oh.Hey",
	"collections": ["redhat"],
	"effective_on": effective_on,
	"msg": "Bad thing foo",
	"severity": "warning",
	"term": "git-clone",
}

_attestation_with_finished_on(finished_on) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"runDetails": {"metadata": {"finishedOn": finished_on}}},
}}

_v02_attestation_with_finished_on(finished_on) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {"metadata": {"buildFinishedOn": finished_on}},
}}

_unsupported_attestation_with_finished_on(finished_on) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/unsupported",
	"predicate": {"runDetails": {"metadata": {"finishedOn": finished_on}}},
}}

test_result_helper_without_package_annotation if {
	expected_result := {
		"code": "package_name.Hey", # Fixme
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [{"annotations": rule_annotations, "path": ["package_name", "deny"]}]

	assertions.assert_equal(expected_result, metadata.result_helper(chain, ["foo"]))
}

test_result_helper_with_collections if {
	expected := {
		"code": "some.path.oh.Hey",
		"collections": ["spam"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"collections": ["spam"],
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": ["some", "path", "oh", "deny"]},
		{"annotations": {}, "path": ["ignored", "ignored"]}, # Actually not needed any more
	]

	assertions.assert_equal(expected, metadata.result_helper(chain, ["foo"]))
}

test_result_helper_with_term if {
	expected := {
		"code": "path.oh.Hey",
		"term": "ola",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Bad thing foo",
	}

	rule_annotations := {"custom": {
		"short_name": "Hey",
		"failure_msg": "Bad thing %s",
	}}

	chain := [
		{"annotations": rule_annotations, "path": ["data", "path", "oh", "deny"]},
		{"annotations": {}, "path": ["ignored", "also_ignored"]},
	]

	assertions.assert_equal(expected, metadata.result_helper_with_term(chain, ["foo"], "ola"))
}

test_result_helper_pkg_name if {
	# "Normal" for policy repo
	assertions.assert_equal("foo", metadata._pkg_name(["data", "foo", "deny"]))
	assertions.assert_equal("foo", metadata._pkg_name(["data", "foo", "warn"]))

	# Long package paths are retained
	assertions.assert_equal("another.foo.bar", metadata._pkg_name(["data", "another", "foo", "bar", "deny"]))
	assertions.assert_equal("another.foo.bar", metadata._pkg_name(["data", "another", "foo", "bar", "warn"]))

	# Unlikely edge case: No deny or warn
	assertions.assert_equal("foo", metadata._pkg_name(["data", "foo"]))
	assertions.assert_equal("foo.bar", metadata._pkg_name(["data", "foo", "bar"]))

	# Unlikely edge case: No data
	assertions.assert_equal("foo", metadata._pkg_name(["foo", "deny"]))
	assertions.assert_equal("foo.bar", metadata._pkg_name(["foo", "bar", "warn"]))

	# Very unlikely edge case: Just to illustrate how deny/warn/data are stripped once
	assertions.assert_equal("foo", metadata._pkg_name(["data", "foo", "warn", "deny"]))
	assertions.assert_equal("foo.deny", metadata._pkg_name(["data", "foo", "deny", "warn"]))
	assertions.assert_equal("foo.warn", metadata._pkg_name(["data", "foo", "warn", "warn"]))
	assertions.assert_equal("data.foo.warn.deny", metadata._pkg_name(["data", "data", "foo", "warn", "deny", "warn"]))
}
