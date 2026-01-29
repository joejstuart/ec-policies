package sbom_spdx_count_001_test

import rego.v1
import data.sbom_spdx_count_001

test_pass_when_condition_met if {
	count(sbom_spdx_count_001.deny) == 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://spdx.dev/Document",
					"predicate": {
						"SPDXID": "SPDXRef-DOCUMENT",
						"spdxVersion": "SPDX-2.3",
						"name": "test-image@sha256:abc123",
						"documentNamespace": "https://example.com/spdxdocs/test-image",
						"dataLicense": "CC0-1.0",
						"creationInfo": {
							"created": "2024-01-01T00:00:00Z",
							"creators": ["Organization: Test Org", "Tool: test-tool-1.0"],
							"licenseListVersion": "3.25"
						},
						"packages": [
							{
								"SPDXID": "SPDXRef-Package-test-1",
								"name": "test-package",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-2",
								"name": "test-package-2",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-3",
								"name": "test-package-3",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-4",
								"name": "test-package-4",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-5",
								"name": "test-package-5",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-6",
								"name": "test-package-6",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-7",
								"name": "test-package-7",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-8",
								"name": "test-package-8",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-9",
								"name": "test-package-9",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							},
							{
								"SPDXID": "SPDXRef-Package-test-10",
								"name": "test-package-10",
								"versionInfo": "1.0.0",
								"downloadLocation": "NOASSERTION",
								"filesAnalyzed": false,
								"licenseDeclared": "NOASSERTION",
								"copyrightText": "NOASSERTION",
								"supplier": "Organization: Test Supplier",
								"checksums": [
									{
										"algorithm": "SHA256",
										"checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
									},
									{
										"algorithm": "SHA1",
										"checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
									}
								],
								"externalRefs": [
									{
										"referenceCategory": "PACKAGE_MANAGER",
										"referenceType": "purl",
										"referenceLocator": "pkg:rpm/test-package@1.0.0"
									}
								]
							}
						],
						"files": []
					}
				}
			}
		]
	}
}
