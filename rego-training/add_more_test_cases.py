#!/usr/bin/env python3
"""Add more test cases to reach 200+ and ensure complete field coverage."""

import json

def add_more_test_cases():
    """Add additional test cases to reach 200+."""
    
    with open("comprehensive_test_cases.json") as f:
        data = json.load(f)
    
    test_cases = data["test_cases"]
    case_num = len(test_cases) + 1
    
    # More task parameter combinations
    additional_cases = [
        {
            "id": f"task_param_{case_num:03d}",
            "natural_language": "Verify the build task has the 'rebuild' parameter set to 'false'.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    task.invocation.parameters.rebuild == "true"
    result := "Build task rebuild parameter is set to true"
}""",
            "keys_used": ["task.name", "task.invocation.parameters.rebuild"],
            "type": "single_key"
        },
        {
            "id": f"task_param_{case_num+1:03d}",
            "natural_language": "Verify the build task has the 'skip-checks' parameter set to 'false'.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    task.invocation.parameters["skip-checks"] == "true"
    result := "Build task skip-checks parameter is set to true"
}""",
            "keys_used": ["task.name", "task.invocation.parameters"],
            "type": "single_key"
        },
        {
            "id": f"compound_{case_num+2:03d}",
            "natural_language": "Verify all tasks that have a 'rebuild' parameter have it set to 'false'.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    rebuild := task.invocation.parameters.rebuild
    rebuild
    rebuild == "true"
    result := sprintf("Task %s has rebuild parameter set to true", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.parameters.rebuild", "task.name"],
            "type": "compound"
        },
        {
            "id": f"compound_{case_num+3:03d}",
            "natural_language": "Verify all tasks that have a 'skip-checks' parameter have it set to 'false'.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    skip_checks := task.invocation.parameters["skip-checks"]
    skip_checks
    skip_checks == "true"
    result := sprintf("Task %s has skip-checks parameter set to true", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.parameters", "task.name"],
            "type": "compound"
        },
        {
            "id": f"step_{case_num+4:03d}",
            "natural_language": "Verify all steps in all tasks have environment image that is not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    image := step.environment.image
    image == ""
    result := sprintf("Task %s has step with empty image", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.image", "task.name"],
            "type": "compound"
        },
        {
            "id": f"step_{case_num+5:03d}",
            "natural_language": "Verify all steps in all tasks have environment container that is not empty when set.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    container := step.environment.container
    container
    container == ""
    result := sprintf("Task %s has step with empty container name", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.container", "task.name"],
            "type": "compound"
        },
        {
            "id": f"materials_{case_num+6:03d}",
            "natural_language": "Verify all materials have URIs that are not empty strings.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    material.uri == ""
    result := "Material has empty URI"
}""",
            "keys_used": ["attestation.statement.predicate.materials", "material.uri"],
            "type": "compound"
        },
        {
            "id": f"materials_{case_num+7:03d}",
            "natural_language": "Verify all materials with SHA1 digest have valid 40-character hex format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    sha1 := material.digest.sha1
    sha1
    not regex.match(`^[a-f0-9]{40}$`, sha1)
    result := sprintf("Material SHA1 digest %s is not valid format", [sha1])
}""",
            "keys_used": ["attestation.statement.predicate.materials", "material.digest.sha1"],
            "type": "compound"
        },
        {
            "id": f"materials_{case_num+8:03d}",
            "natural_language": "Verify all materials with SHA256 digest have valid 64-character hex format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    sha256 := material.digest.sha256
    sha256
    not regex.match(`^[a-f0-9]{64}$`, sha256)
    result := sprintf("Material SHA256 digest %s is not valid format", [sha256])
}""",
            "keys_used": ["attestation.statement.predicate.materials", "material.digest.sha256"],
            "type": "compound"
        },
        {
            "id": f"subject_{case_num+9:03d}",
            "natural_language": "Verify all subject images have SHA256 digests in valid 64-character hex format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    sha256 := subject.digest.sha256
    sha256
    not regex.match(`^[a-f0-9]{64}$`, sha256)
    result := sprintf("Subject image %s has invalid SHA256 digest format", [subject.name])
}""",
            "keys_used": ["attestation.statement.subject", "subject.digest.sha256", "subject.name"],
            "type": "compound"
        },
        {
            "id": f"subject_{case_num+10:03d}",
            "natural_language": "Verify all subject images have names that are not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    subject.name == ""
    result := "Subject image has empty name"
}""",
            "keys_used": ["attestation.statement.subject", "subject.name"],
            "type": "compound"
        },
        {
            "id": f"configSource_{case_num+11:03d}",
            "natural_language": "Verify all tasks have configSource with uri that is not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    uri := task.invocation.configSource.uri
    uri
    uri == ""
    result := sprintf("Task %s configSource has empty uri", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.configSource.uri", "task.name"],
            "type": "compound"
        },
        {
            "id": f"configSource_{case_num+12:03d}",
            "natural_language": "Verify all tasks have configSource with entryPoint that is not empty when set.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    entry_point := task.invocation.configSource.entryPoint
    entry_point
    entry_point == ""
    result := sprintf("Task %s configSource has empty entryPoint", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.configSource.entryPoint", "task.name"],
            "type": "compound"
        },
        {
            "id": f"configSource_{case_num+13:03d}",
            "natural_language": "Verify all tasks have configSource digest with sha256 that is not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    digest := task.invocation.configSource.digest
    digest
    digest.sha256 == ""
    result := sprintf("Task %s configSource digest has empty sha256", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.configSource.digest.sha256", "task.name"],
            "type": "compound"
        },
        {
            "id": f"ref_{case_num+14:03d}",
            "natural_language": "Verify all tasks have reference name that is not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.ref.name == ""
    result := sprintf("Task %s reference has empty name", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.ref.name", "task.name"],
            "type": "compound"
        },
        {
            "id": f"ref_{case_num+15:03d}",
            "natural_language": "Verify all tasks have reference kind that is not empty.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.ref.kind == ""
    result := sprintf("Task %s reference has empty kind", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.ref.kind", "task.name"],
            "type": "compound"
        },
        {
            "id": f"ref_{case_num+16:03d}",
            "natural_language": "Verify all tasks that have reference params have at least one param.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.ref.params
    count(task.ref.params) == 0
    result := sprintf("Task %s reference has empty params array", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.ref.params", "task.name"],
            "type": "compound"
        },
        {
            "id": f"result_{case_num+17:03d}",
            "natural_language": "Verify all tasks that have results have at least one result with a name.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some task_result in task.results
    not task_result.name
    result := sprintf("Task %s has result without name", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.results", "task.name", "result.name"],
            "type": "compound"
        },
        {
            "id": f"result_{case_num+18:03d}",
            "natural_language": "Verify all tasks that have results have unique result names.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    result_names := {r.name | some r in task.results}
    all_result_names := [r.name | some r in task.results]
    count(result_names) != count(all_result_names)
    result := sprintf("Task %s has duplicate result names", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.results", "task.name"],
            "type": "compound"
        },
        {
            "id": f"annotation_{case_num+19:03d}",
            "natural_language": "Verify all tasks have annotation values that are not empty when the annotation exists.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some annotation_key, annotation_value in task.invocation.environment.annotations
    annotation_value == ""
    result := sprintf("Task %s has annotation %s with empty value", [task.name, annotation_key])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.annotations", "task.name"],
            "type": "compound"
        },
        {
            "id": f"label_{case_num+20:03d}",
            "natural_language": "Verify all tasks have label values that are not empty when the label exists.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some label_key, label_value in task.invocation.environment.labels
    label_value == ""
    result := sprintf("Task %s has label %s with empty value", [task.name, label_key])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.labels", "task.name"],
            "type": "compound"
        },
        {
            "id": f"timestamp_{case_num+21:03d}",
            "natural_language": "Verify all tasks that have startedOn have it in valid RFC3339 format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    started := task.startedOn
    started
    not time.parse_rfc3339_ns(started)
    result := sprintf("Task %s has invalid startedOn timestamp format: %s", [task.name, started])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.startedOn", "task.name"],
            "type": "compound"
        },
        {
            "id": f"timestamp_{case_num+22:03d}",
            "natural_language": "Verify all tasks that have finishedOn have it in valid RFC3339 format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    finished := task.finishedOn
    finished
    not time.parse_rfc3339_ns(finished)
    result := sprintf("Task %s has invalid finishedOn timestamp format: %s", [task.name, finished])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.finishedOn", "task.name"],
            "type": "compound"
        },
        {
            "id": f"metadata_{case_num+23:03d}",
            "natural_language": "Verify the build started timestamp is in valid RFC3339 format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    started := attestation.statement.predicate.metadata.buildStartedOn
    started
    not time.parse_rfc3339_ns(started)
    result := sprintf("Build startedOn timestamp has invalid format: %s", [started])
}""",
            "keys_used": ["attestation.statement.predicate.metadata.buildStartedOn"],
            "type": "single_key"
        },
        {
            "id": f"metadata_{case_num+24:03d}",
            "natural_language": "Verify the build finished timestamp is in valid RFC3339 format.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    finished := attestation.statement.predicate.metadata.buildFinishedOn
    finished
    not time.parse_rfc3339_ns(finished)
    result := sprintf("Build finishedOn timestamp has invalid format: %s", [finished])
}""",
            "keys_used": ["attestation.statement.predicate.metadata.buildFinishedOn"],
            "type": "single_key"
        },
        {
            "id": f"slsa_v1_{case_num+25:03d}",
            "natural_language": "Verify the SLSA v1.0 attestation externalParameters has runSpec with pipelineSpec.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.externalParameters.runSpec.pipelineSpec
    result := "SLSA v1.0 attestation externalParameters.runSpec does not have pipelineSpec"
}""",
            "keys_used": ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.externalParameters.runSpec.pipelineSpec"],
            "type": "single_key"
        },
        {
            "id": f"slsa_v1_{case_num+26:03d}",
            "natural_language": "Verify the SLSA v1.0 attestation internalParameters has labels.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.internalParameters.labels
    result := "SLSA v1.0 attestation internalParameters does not have labels"
}""",
            "keys_used": ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.internalParameters.labels"],
            "type": "single_key"
        },
        {
            "id": f"slsa_v1_{case_num+27:03d}",
            "natural_language": "Verify the SLSA v1.0 attestation internalParameters has annotations.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.internalParameters.annotations
    result := "SLSA v1.0 attestation internalParameters does not have annotations"
}""",
            "keys_used": ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.internalParameters.annotations"],
            "type": "single_key"
        },
        {
            "id": f"compound_{case_num+28:03d}",
            "natural_language": "Verify all tasks have both started and finished timestamps when they have a status.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status
    (not task.startedOn or not task.finishedOn)
    result := sprintf("Task %s has status but missing timestamps", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.status", "task.startedOn", "task.finishedOn", "task.name"],
            "type": "compound"
        },
        {
            "id": f"compound_{case_num+29:03d}",
            "natural_language": "Verify all tasks that have steps have at least one step with a non-empty entryPoint.",
            "rego_code": """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    count(task.steps) > 0
    all_empty := {step.entryPoint | some step in task.steps; step.entryPoint == ""}
    count(all_empty) == count(task.steps)
    result := sprintf("Task %s has all steps with empty entryPoint", [task.name])
}""",
            "keys_used": ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.entryPoint", "task.name"],
            "type": "compound"
        },
    ]
    
    # Add all additional cases
    for case in additional_cases:
        test_cases[case["id"]] = {
            "natural_language": case["natural_language"],
            "rego_code": case["rego_code"],
            "keys_used": case["keys_used"],
            "type": case["type"]
        }
    
    # Update metadata
    single_key = sum(1 for v in test_cases.values() if v.get("type") == "single_key")
    compound = sum(1 for v in test_cases.values() if v.get("type") == "compound")
    
    data["metadata"]["total_test_cases"] = len(test_cases)
    data["metadata"]["single_key_cases"] = single_key
    data["metadata"]["compound_cases"] = compound
    data["test_cases"] = test_cases
    
    with open("comprehensive_test_cases.json", "w") as f:
        json.dump(data, f, indent=2)
    
    print(f"Updated to {len(test_cases)} test cases")
    print(f"  Single key: {single_key}")
    print(f"  Compound: {compound}")

if __name__ == "__main__":
    add_more_test_cases()
