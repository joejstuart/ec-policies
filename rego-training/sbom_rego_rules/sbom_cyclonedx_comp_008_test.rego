package sbom_cyclonedx_comp_008_test

import rego.v1
import data.sbom_cyclonedx_comp_008

test_pass_when_condition_met if {
	count(sbom_cyclonedx_comp_008.deny) == 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://cyclonedx.org/bom",
					"predicate": {
						"bomFormat": "CycloneDX",
						"specVersion": "1.5",
						"version": 1,
						"serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
						"metadata": {
							"timestamp": "2024-01-01T00:00:00Z",
							"tools": [
								{
									"vendor": "Test Vendor",
									"name": "test-tool",
									"version": "1.0.0"
								}
							],
							"component": {
								"type": "container",
								"name": "test-image",
								"bom-ref": "test-image-ref"
							}
						},
						"components": [
							{
								"type": "library",
								"name": "test-component",
								"version": "1.0.0",
								"bom-ref": "test-component-ref",
								"purl": "pkg:rpm/test-component@1.0.0",
								"licenses": [
									{
										"license": {
											"name": "MIT"
										}
									}
								]
							}
						]
					}
				}
			}
		]
	}
}
