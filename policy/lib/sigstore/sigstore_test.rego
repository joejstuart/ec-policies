package lib.sigstore_test

import rego.v1

import data.lib.assertions
import data.lib.sigstore

test_sigstore_opts if {
	assertions.assert_equal(sigstore.opts, {
		"certificate_identity": "",
		"certificate_identity_regexp": "",
		"certificate_oidc_issuer": "",
		"certificate_oidc_issuer_regexp": "",
		"ignore_rekor": false,
		"public_key": "",
		"rekor_public_key": "",
		"rekor_url": "",
	})

	opts := {
		"certificate_identity": "subject",
		"certificate_identity_regexp": "subject-regexp",
		"certificate_oidc_issuer": "issuer",
		"certificate_oidc_issuer_regexp": "issuer-regexp",
		"ignore_rekor": true,
		"public_key": "public-key",
		"rekor_public_key": "rekor-public-key",
		"rekor_url": "https://rekor.local",
	}
	assertions.assert_equal(sigstore.opts, opts) with data.config.default_sigstore_opts as opts
}

test_validate_schema_errors if {
	identity := {
		"public_key": 42,
		"ignore_rekor": "not-a-bool",
		"unknown_field": "should-not-be-here",
	}

	errors := sigstore.validate(identity)
	msgs := {e.message | some e in errors}

	every msg in {
		"public_key: Invalid type. Expected: string, given: integer",
		"ignore_rekor: Invalid type. Expected: boolean, given: string",
		"(Root): Additional property unknown_field is not allowed",
	} {
		msg in msgs
	}
}

test_validate_no_verification_method if {
	errors := sigstore.validate({"ignore_rekor": true})

	assertions.assert_equal(count(errors), 1)

	# regal ignore:line-length
	assertions.assert_equal(errors[0].message, "must specify public_key or certificate identity (certificate_identity or certificate_identity_regexp)")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_empty_object if {
	errors := sigstore.validate({})

	assertions.assert_equal(count(errors), 1)

	# regal ignore:line-length
	assertions.assert_equal(errors[0].message, "must specify public_key or certificate identity (certificate_identity or certificate_identity_regexp)")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_non_object if {
	assertions.assert_equal(sigstore.validate("not-an-object"), [])
	assertions.assert_equal(sigstore.validate(42), [])
	assertions.assert_equal(sigstore.validate(null), [])
}

test_validate_keyless_missing_issuer if {
	identity := {
		"certificate_identity": "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
		"rekor_url": "https://rekor.sigstore.dev",
	}

	errors := sigstore.validate(identity)

	assertions.assert_equal(count(errors), 1)

	# regal ignore:line-length
	assertions.assert_equal(errors[0].message, "requires certificate_oidc_issuer or certificate_oidc_issuer_regexp for keyless verification")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_keyless_missing_rekor if {
	identity := {
		"certificate_identity": "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
		"certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
	}

	errors := sigstore.validate(identity)

	assertions.assert_equal(count(errors), 1)
	assertions.assert_equal(errors[0].message, "requires rekor_url for keyless verification")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_key_based_missing_rekor_config if {
	errors := sigstore.validate({"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH..."})

	assertions.assert_equal(count(errors), 1)

	# regal ignore:line-length
	assertions.assert_equal(errors[0].message, "requires rekor_url, rekor_public_key, or ignore_rekor when using public_key verification")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_keyless_regexp_missing_issuer if {
	identity := {
		"certificate_identity_regexp": "https://github.com/org/.*",
		"rekor_url": "https://rekor.sigstore.dev",
	}

	errors := sigstore.validate(identity)

	assertions.assert_equal(count(errors), 1)

	# regal ignore:line-length
	assertions.assert_equal(errors[0].message, "requires certificate_oidc_issuer or certificate_oidc_issuer_regexp for keyless verification")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_keyless_regexp_missing_rekor if {
	identity := {
		"certificate_identity_regexp": "https://github.com/org/.*",
		"certificate_oidc_issuer_regexp": "https://token.actions.*",
	}

	errors := sigstore.validate(identity)

	assertions.assert_equal(count(errors), 1)
	assertions.assert_equal(errors[0].message, "requires rekor_url for keyless verification")
	assertions.assert_equal(errors[0].severity, "failure")
}

test_validate_valid_key_ignore_rekor if {
	assertions.assert_equal(
		sigstore.validate({
			"public_key": "k8s://namespace/secret",
			"ignore_rekor": true,
		}),
		[],
	)
}

test_validate_valid_key_online_rekor if {
	assertions.assert_equal(
		sigstore.validate({
			"public_key": "k8s://namespace/secret",
			"rekor_url": "https://rekor.sigstore.dev",
		}),
		[],
	)
}

test_validate_valid_key_offline_rekor if {
	assertions.assert_equal(
		sigstore.validate({
			"public_key": "k8s://namespace/secret",
			"rekor_public_key": "-----BEGIN PUBLIC KEY-----\n...",
		}),
		[],
	)
}

test_validate_valid_keyless_exact if {
	assertions.assert_equal(
		sigstore.validate({
			"certificate_identity": "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
			"certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
			"rekor_url": "https://rekor.sigstore.dev",
		}),
		[],
	)
}

test_validate_valid_keyless_regexp if {
	assertions.assert_equal(
		sigstore.validate({
			"certificate_identity_regexp": "https://github.com/org/.*",
			"certificate_oidc_issuer_regexp": "https://token.actions.*",
			"rekor_url": "https://rekor.sigstore.dev",
		}),
		[],
	)
}

test_validate_valid_keyless_mixed if {
	assertions.assert_equal(
		sigstore.validate({
			"certificate_identity": "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main",
			"certificate_oidc_issuer_regexp": "https://token.actions.*",
			"rekor_url": "https://rekor.sigstore.dev",
		}),
		[],
	)
}

# --- Tests for the shared signing_identities helpers ---

test_named_identity_returns_entry if {
	d := {"signing_identities": {"rh-release": {"public_key": "key", "ignore_rekor": true}}}
	assertions.assert_equal(
		sigstore.named_identity("rh-release"),
		{"public_key": "key", "ignore_rekor": true},
	) with data.rule_data as d
}

test_named_identity_absent if {
	not sigstore.named_identity("rh-release") with data.rule_data as {}
}

test_identity_rule_data_errors_valid if {
	d := {"signing_identities": {"sbom": {"public_key": "key", "ignore_rekor": true}}}
	assertions.assert_empty(sigstore.identity_rule_data_errors("sbom")) with data.rule_data as d
}

test_identity_rule_data_errors_absent if {
	assertions.assert_empty(sigstore.identity_rule_data_errors("sbom")) with data.rule_data as {}
}

test_identity_rule_data_errors_top_level_not_object if {
	errors := sigstore.identity_rule_data_errors("sbom") with data.rule_data as {"signing_identities": 42}
	msgs := {e.message | some e in errors}
	"Rule data signing_identities has unexpected format: expected an object, got number" in msgs
}

test_identity_rule_data_errors_entry_not_object if {
	d := {"signing_identities": {"sbom": "not-an-object"}}
	errors := sigstore.identity_rule_data_errors("sbom") with data.rule_data as d
	msgs := {e.message | some e in errors}
	"Rule data signing_identities.sbom has unexpected format: expected an object, got string" in msgs
}

test_identity_rule_data_errors_invalid_config if {
	d := {"signing_identities": {"sbom": {"public_key": "key"}}}
	errors := sigstore.identity_rule_data_errors("sbom") with data.rule_data as d
	msgs := {e.message | some e in errors}

	# regal ignore:line-length
	"Rule data signing_identities.sbom requires rekor_url, rekor_public_key, or ignore_rekor when using public_key verification" in msgs
}

# The default helper warns when a configured, non-empty map omits the key.
test_identity_rule_data_errors_missing_key_warns if {
	d := {"signing_identities": {"other": {"public_key": "key", "ignore_rekor": true}}}
	errors := sigstore.identity_rule_data_errors("sbom") with data.rule_data as d
	assertions.assert_equal(errors, {{
		"message": "Rule data signing_identities does not contain the expected key \"sbom\"",
		"severity": "warning",
	}}) with data.rule_data as d
}

# The optional helper stays silent when the identity is absent from the map.
test_optional_identity_rule_data_errors_missing_key_silent if {
	d := {"signing_identities": {"other": {"public_key": "key", "ignore_rekor": true}}}
	assertions.assert_empty(sigstore.optional_identity_rule_data_errors("sbom")) with data.rule_data as d
}

# The optional helper still validates a present but malformed entry.
test_optional_identity_rule_data_errors_validates_present if {
	d := {"signing_identities": {"sbom": {"public_key": "key"}}}
	errors := sigstore.optional_identity_rule_data_errors("sbom") with data.rule_data as d
	msgs := {e.message | some e in errors}

	# regal ignore:line-length
	"Rule data signing_identities.sbom requires rekor_url, rekor_public_key, or ignore_rekor when using public_key verification" in msgs
}
