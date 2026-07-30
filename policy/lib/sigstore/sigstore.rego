package lib.sigstore

import rego.v1

import data.lib.json as j
import data.lib.rule_data

# opts provides a safe way to access the default sigstore opts. It ensures policy rules
# don't accidentally evaluate to passing if the default values are not in the config.
default opts := {
	"certificate_identity": "",
	"certificate_identity_regexp": "",
	"certificate_oidc_issuer": "",
	"certificate_oidc_issuer_regexp": "",
	"ignore_rekor": false,
	"public_key": "",
	"rekor_public_key": "",
	"rekor_url": "",
}

opts := data.config.default_sigstore_opts

validate(identity) := [e |
	some checks in [
		_validate_schema(identity),
		_validate_method(identity),
		_validate_keyless_issuer(identity),
		_validate_keyless_rekor(identity),
		_validate_key_rekor(identity),
	]
	some e in checks
] if {
	is_object(identity)
} else := []

opts_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "object",
	"properties": {
		"public_key": {"type": "string"},
		"certificate_identity": {"type": "string"},
		"certificate_identity_regexp": {"type": "string"},
		"certificate_oidc_issuer": {"type": "string"},
		"certificate_oidc_issuer_regexp": {"type": "string"},
		"ignore_rekor": {"type": "boolean"},
		"rekor_url": {"type": "string"},
		"rekor_public_key": {"type": "string"},
	},
	"additionalProperties": false,
}

_validate_schema(identity) := [{"message": e.message, "severity": e.severity} |
	some e in j.validate_schema(identity, opts_schema)
]

_validate_method(identity) := [error] if {
	not _has_value(identity, "public_key")
	not _has_value(identity, "certificate_identity")
	not _has_value(identity, "certificate_identity_regexp")

	# regal ignore:line-length
	error := {"message": "must specify public_key or certificate identity (certificate_identity or certificate_identity_regexp)", "severity": "failure"}
} else := []

_validate_keyless_issuer(identity) := [error] if {
	not _has_value(identity, "public_key")
	_has_certificate_identity(identity)
	not _has_value(identity, "certificate_oidc_issuer")
	not _has_value(identity, "certificate_oidc_issuer_regexp")

	# regal ignore:line-length
	error := {"message": "requires certificate_oidc_issuer or certificate_oidc_issuer_regexp for keyless verification", "severity": "failure"}
} else := []

_validate_keyless_rekor(identity) := [error] if {
	not _has_value(identity, "public_key")
	_has_certificate_identity(identity)
	_has_certificate_oidc_issuer(identity)
	not _has_value(identity, "rekor_url")
	error := {"message": "requires rekor_url for keyless verification", "severity": "failure"}
} else := []

_validate_key_rekor(identity) := [error] if {
	_has_value(identity, "public_key")
	object.get(identity, "ignore_rekor", false) != true
	not _has_value(identity, "rekor_url")
	not _has_value(identity, "rekor_public_key")

	# regal ignore:line-length
	error := {"message": "requires rekor_url, rekor_public_key, or ignore_rekor when using public_key verification", "severity": "failure"}
} else := []

_has_value(obj, key) if {
	val := object.get(obj, key, "")
	val != ""
}

_has_certificate_identity(identity) if _has_value(identity, "certificate_identity")

_has_certificate_identity(identity) if _has_value(identity, "certificate_identity_regexp")

_has_certificate_oidc_issuer(identity) if _has_value(identity, "certificate_oidc_issuer")

_has_certificate_oidc_issuer(identity) if _has_value(identity, "certificate_oidc_issuer_regexp")

# signing_identities_key is the rule data key holding the named signing
# identities map that policy rules verify signatures against.
signing_identities_key := "signing_identities"

# named_identity returns the signing identity configured under name within the
# signing_identities rule data. It is undefined when no such identity is
# configured, letting consumers fail closed.
named_identity(name) := rule_data.get(signing_identities_key)[name]

# identity_rule_data_errors validates the signing_identities rule data for a
# named identity that is expected to be configured. It returns a set of
# {message, severity} objects covering the top-level map shape, the named
# entry's shape, the entry's sigstore verification config (via validate), and a
# warning when the map is configured with entries but omits the expected name.
# Consumers where the identity is optional should use
# optional_identity_rule_data_errors instead.
identity_rule_data_errors(name) := optional_identity_rule_data_errors(name) | _identity_presence_errors(name)

# optional_identity_rule_data_errors validates a signing identity only when one
# is configured under name: the top-level map shape, the entry's shape, and the
# entry's verification config. It stays silent when the identity is absent, so
# consumers can fail closed without emitting a warning. The set is empty when
# the identity is absent or valid.
optional_identity_rule_data_errors(name) := errors if {
	shape_errors := _signing_identities_shape_errors | _identity_entry_shape_errors(name)
	errors := shape_errors | _identity_validate_errors(name)
}

# _identity_presence_errors warns when signing_identities is configured with
# entries but is missing the expected name. Included by identity_rule_data_errors
# for consumers that require the identity to be present.
_identity_presence_errors(name) := {error |
	identities := rule_data.get(signing_identities_key)
	is_object(identities)
	count(identities) > 0
	not name in object.keys(identities)
	error := {
		"message": sprintf(
			"Rule data %s does not contain the expected key %q",
			[signing_identities_key, name],
		),
		"severity": "warning",
	}
}

_signing_identities_shape_errors contains error if {
	val := rule_data.get(signing_identities_key)
	val != []
	not is_object(val)
	error := {
		"message": sprintf(
			"Rule data %s has unexpected format: expected an object, got %s",
			[signing_identities_key, type_name(val)],
		),
		"severity": "failure",
	}
}

_identity_entry_shape_errors(name) := {error |
	identities := rule_data.get(signing_identities_key)
	is_object(identities)
	val := object.get(identities, name, {})
	val != {}
	not is_object(val)
	error := {
		"message": sprintf(
			"Rule data %s.%s has unexpected format: expected an object, got %s",
			[signing_identities_key, name, type_name(val)],
		),
		"severity": "failure",
	}
}

_identity_validate_errors(name) := {error |
	some e in validate(named_identity(name))
	error := {
		"message": sprintf("Rule data %s.%s %s", [signing_identities_key, name, e.message]),
		"severity": e.severity,
	}
}
