package slsa_v1_038_test

import rego.v1
import data.slsa_v1_038

test_deny_when_metadata_missing if {
	count(slsa_v1_038.deny) > 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v1",
					"subject": [
						{
							"name": "test-image",
							"digest": {
								"sha256": "abc123"
							}
						}
					],
					"predicate": {
						"runDetails": {}
					}
				}
			}
		]
	}
}

test_pass_when_metadata_exists if {
	count(slsa_v1_038.deny) == 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v1",
					"subject": [
						{
							"name": "test-image",
							"digest": {
								"sha256": "abc123"
							}
						}
					],
					"predicate": {
						"runDetails": {
							"metadata": {}
						}
					}
				}
			}
		]
	}
}
