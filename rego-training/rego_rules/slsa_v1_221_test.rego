package slsa_v1_221_test

import rego.v1
import data.slsa_v1_221

test_deny_when_predicateType_wrong if {
	count(slsa_v1_221.deny) > 0
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
						"buildDefinition": {
							"internalParameters": {}
						}
					}
				}
			}
		]
	}
}

test_pass_when_predicateType_correct if {
	count(slsa_v1_221.deny) == 0
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
						"buildDefinition": {
							"internalParameters": {
								"labels": {}
							}
						}
					}
				}
			}
		]
	}
}
