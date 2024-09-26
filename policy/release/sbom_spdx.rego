#
# METADATA
# title: SPDX SBOM
# description: >-
#   Checks different properties of the SPDX SBOM attestation.
#
package policy.release.sbom_spdx

import rego.v1

import data.lib
import data.lib.image
import data.lib.sbom

# METADATA
# title: Found
# description: Confirm an SPDX SBOM attestation exists.
# custom:
#   short_name: found
#   failure_msg: No SPDX SBOM attestations found
#   solution: >-
#     Make sure the build process produces an SPDX SBOM attestation.
#
deny contains result if {
	count(_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Valid
# description: >-
#   Check the SPDX SBOM has the expected format. It verifies the SPDX SBOM matches the 1.5
#   version of the schema.
# custom:
#   short_name: valid
#   failure_msg: 'SPDX SBOM at index %d is not valid: %s'
#   solution: Make sure the build process produces a valid SPDX SBOM.
#   collections:
#   - minimal
#   - redhat
#
deny contains result if {
	some index, s in _sboms
	some violation in json.match_schema(s, schema_2_3)[1]
	error := violation.error
	result := lib.result_helper(rego.metadata.chain(), [index, error])
}

# METADATA
# title: Contains packages
# description: Check the list of packages in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_packages
#   failure_msg: The list of packages is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the package in the image.
#
deny contains result if {
	some sbom in _sboms
	count(sbom.packages) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed
# description: >-
#   Confirm the SPDX SBOM contains only allowed packages. By default all packages are allowed.
#   Use the "disallowed_packages" rule data key to provide a list of disallowed packages.
# custom:
#   short_name: allowed
#   failure_msg: "Package is not allowed: %s"
#   solution: >-
#     Update the image to not use a disallowed package.
#   collections:
#   - redhat
#
deny contains result if {
	some s in _sboms
	some pkg in s.packages
	some ref in pkg.externalRefs
	ref.referenceType == "purl"	
	_contains(ref.referenceLocator, lib.rule_data(_rule_data_packages_key))
	result := lib.result_helper(rego.metadata.chain(), [ref.referenceLocator])
}

# METADATA
# title: Contains files
# description: Check the list of files in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_files
#   failure_msg: The list of files is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the files in the image.
#
deny contains result if {
	some sbom in _sboms
	count(sbom.files) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Matches image
# description: Check the SPDX SBOM targets the image being validated.
# custom:
#   short_name: matches_image
#   failure_msg: Image digest in the SBOM, %q, is not as expected, %q
#   solution: >-
#     The SPDX SBOM associated with the image describes a different image.
#     Verify the integrity of the build system.
#
deny contains result if {
	some sbom in _sboms
	sbom_image := image.parse(sbom.name)
	expected_image := image.parse(input.image.ref)
	sbom_image.digest != expected_image.digest
	result := lib.result_helper(rego.metadata.chain(), [sbom_image.digest, expected_image.digest])
}

_sboms := [sbom |
	some att in input.attestations
	att.statement.predicateType == "https://spdx.dev/Document"
	sbom := _predicate(att)
]

# _is_valid is true if the given SPDX SBOM has certain fields. This is
# not an exhaustive schema check. It mostly ensures the fields used
# by the policy rules in this package have been set.
_is_valid(sbom) if {
	sbom.name
	name_ref := image.parse(sbom.name)
	count(name_ref.digest) > 0
	is_array(sbom.files)
	is_array(sbom.packages)
}

# _predicate returns the predicate from the given attestation. If the
# predicate is JSON marshaled, it is unmarshaled.
_predicate(att) := predicate if {
	json.is_valid(att.statement.predicate)
	predicate := json.unmarshal(att.statement.predicate)
} else := att.statement.predicate

_contains(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)

	not _excluded(needle_purl, object.get(hay, "exceptions", []))
} else := false

_excluded(purl, exceptions) if {
	matches := [exception |
		some exception in exceptions
		exception.subpath == purl.subpath
	]
	count(matches) > 0
}

_matches_version(version, matcher) if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	matcher.max != ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	object.get(matcher, "max", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.max != ""
	object.get(matcher, "min", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else := false

_to_semver(v) := trim_prefix(v, "v")

_rule_data_packages_key := "disallowed_packages"
