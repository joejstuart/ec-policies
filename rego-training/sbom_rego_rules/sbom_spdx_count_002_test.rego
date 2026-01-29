package sbom_spdx_count_002_test

import rego.v1
import data.sbom_spdx_count_002

test_pass_when_condition_met if {
	count(sbom_spdx_count_002.deny) == 0
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
							}
						],
						"files": [
							{
								"SPDXID": "SPDXRef-File-test-1",
								"fileName": "test-1.txt"
							},
							{
								"SPDXID": "SPDXRef-File-test-2",
								"fileName": "test-2.txt"
							},
							{
								"SPDXID": "SPDXRef-File-test-3",
								"fileName": "test-3.txt"
							},
							{
								"SPDXID": "SPDXRef-File-test-4",
								"fileName": "test-4.txt"
							},
							{
								"SPDXID": "SPDXRef-File-test-5",
								"fileName": "test-5.txt"
							}
						]
					}
				}
			}
		]
	}
}
