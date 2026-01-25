package metadata_014_test

import rego.v1
import data.metadata_014

test_deny_when_condition_violated if {
	count(metadata_014.deny) > 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
					"subject": [
						{
							"name": "test-image",
							"digest": {
								"sha256": "abc123"
							}
						}
					],
					"predicate": {
						"buildType": "tekton.dev/v1/PipelineRun",
						"materials": [
							{
								"uri": "https://example.com/source"
							}
						],
						"metadata": {
							"buildStartedOn": "2024-01-01T00:00:00Z",
							"buildFinishedOn": "2024-01-01T01:00:00Z",
							"completeness": {
								"parameters": false,
								"environment": true,
								"materials": true
							}
						},
						"buildConfig": {
							"tasks": []
						}
					}
				}
			}
		]
	}
}

test_pass_when_condition_met if {
	count(metadata_014.deny) == 0
	with input as {
		"attestations": [
			{
				"statement": {
					"_type": "https://in-toto.io/Statement/v0.1",
					"predicateType": "https://slsa.dev/provenance/v0.2",
					"subject": [
						{
							"name": "test-image",
							"digest": {
								"sha256": "abc123"
							}
						}
					],
					"predicate": {
						"buildType": "tekton.dev/v1/PipelineRun",
						"materials": [
							{
								"uri": "https://example.com/source"
							}
						],
						"metadata": {
							"buildStartedOn": "2024-01-01T00:00:00Z",
							"buildFinishedOn": "2024-01-01T01:00:00Z",
							"completeness": {
								"parameters": true,
								"environment": true,
								"materials": true
							}
						},
						"buildConfig": {
							"tasks": []
						}
					}
				}
			}
		]
	}
}
