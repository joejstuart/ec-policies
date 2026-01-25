package single_key_038_test

import rego.v1
import data.single_key_038

test_deny_when_condition_violated if {
	count(single_key_038.deny) > 0
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
							"tasks": [
								{
									"name": "build",
									"status": "Succeeded",
									"ref": {
										"name": "build",
										"kind": "Task"
									},
									"invocation": {
										"parameters": {
											"param1": "value1"
										},
										"environment": {
											"annotations": {
												"other-key": "value"
											},
											"labels": {}
										},
										"configSource": {
											"uri": "https://example.com",
											"digest": {
												"sha256": "abc123"
											}
										}
									},
									"results": [
										{
											"name": "result1",
											"value": "value1"
										}
									],
									"steps": [
										{
											"entryPoint": "step1"
										}
									],
									"startedOn": "2024-01-01T00:00:00Z",
									"finishedOn": "2024-01-01T01:00:00Z"
								}
							]
						}
					}
				}
			}
		]
	}
}

test_pass_when_condition_met if {
	count(single_key_038.deny) == 0
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
							"tasks": [
								{
									"name": "build",
									"status": "Succeeded",
									"ref": {
										"name": "build",
										"kind": "Task"
									},
									"invocation": {
										"parameters": {
											"param1": "value1"
										},
										"environment": {
											"annotations": {
												"results.tekton.dev/record": "value"
											},
											"labels": {}
										},
										"configSource": {
											"uri": "https://example.com",
											"digest": {
												"sha256": "abc123"
											}
										}
									},
									"results": [
										{
											"name": "result1",
											"value": "value1"
										}
									],
									"steps": [
										{
											"entryPoint": "step1"
										}
									],
									"startedOn": "2024-01-01T00:00:00Z",
									"finishedOn": "2024-01-01T01:00:00Z"
								}
							]
						}
					}
				}
			}
		]
	}
}
