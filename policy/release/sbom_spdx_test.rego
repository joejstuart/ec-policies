package policy.release.sbom_spdx_test

import rego.v1

import data.lib
import data.policy.release.sbom_spdx

test_all_good if {
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_all_good_marshaled if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate",
		"value": json.marshal(_sbom_attestation.statement.predicate),
	}])
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_found if {
	expected := {{"code": "sbom_spdx.found", "msg": "No SPDX SBOM attestations found"}}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as []
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_packages if {
	expected := {{"code": "sbom_spdx.contains_packages", "msg": "The list of packages is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_files if {
	expected := {{"code": "sbom_spdx.contains_files", "msg": "The list of files is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/files",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_digest_mismatch if {
	expected := {{
		"code": "sbom_spdx.matches_image",
		"msg": "Image digest in the SBOM, \"sha256:123\", is not as expected, \"sha256:abc\"",
	}}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:abc"
}

test_not_valid if {
	expected := {{
		"code": "sbom_spdx.valid",
		"msg": "SPDX SBOM at index 0 is not valid: packages: Invalid type. Expected: array, given: string",
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages",
		"value": "spam",
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
}

_sbom_attestation := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "registry.local/bacon@sha256:123",
		"creationInfo": {
      		"created": "2006-08-14T02:34:56-06:00",
      		"creators": [
        		"Tool: example SPDX document only"
      		]
    	},
		"packages": [
			{
				"SPDXID": "SPDXRef-image-index",
				"name": "spam",
				"versionInfo": "1.1.2-25",
				"supplier": "Organization: Red Hat",
				"downloadLocation": "NOASSERTION",
				"licenseDeclared": "Apache-2.0",
				"externalRefs": [
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					"referenceLocator": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98"
				}
				],
				"checksums": [
				{
					"algorithm": "SHA256",
					"checksumValue": "d845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98"
				}
				]
			}
		],
		"files": [{
			"fileName": "/usr/bin/spam",
			"SPDXID": "SPDXRef-File-usr-bin-spam-0e18b4ee77321ba5",
			"checksums": [
          		{
            		"algorithm": "SHA256",
            		"checksumValue": "d845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98"
          		}
        	]
		}],
	},
}}
