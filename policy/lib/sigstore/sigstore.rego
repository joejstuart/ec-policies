package lib.sigstore

import rego.v1

import data.lib.json as j

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
