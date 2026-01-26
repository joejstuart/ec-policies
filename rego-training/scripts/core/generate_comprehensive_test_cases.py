#!/usr/bin/env python3
"""
Generate comprehensive test cases covering all fields in the attestation structure.

This script generates 200+ test cases covering:
- Top-level fields (_type, predicateType, subject)
- Metadata fields (buildFinishedOn, buildStartedOn, completeness, reproducible)
- Materials fields (uri, digest)
- All task fields
- All step fields
- SLSA v1.0 fields
"""

import json
from typing import Dict, List

def generate_test_case(id: str, natural_language: str, rego_code: str, keys_used: List[str], type: str) -> Dict:
    """Generate a test case entry."""
    return {
        "natural_language": natural_language,
        "rego_code": rego_code,
        "keys_used": keys_used,
        "type": type
    }

def generate_all_test_cases() -> Dict:
    """Generate all test cases covering every field."""
    test_cases = {}
    case_num = 1
    
    # ============================================================================
    # TOP-LEVEL FIELDS (Statement, PredicateType, Subject)
    # ============================================================================
    
    # Statement _type
    test_cases[f"top_level_{case_num:03d}"] = generate_test_case(
        f"top_level_{case_num:03d}",
        "Verify the attestation statement has the correct _type field.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement._type != "https://in-toto.io/Statement/v0.1"
    result := sprintf("Attestation has incorrect _type: %s", [attestation.statement._type])
}""",
        ["attestation.statement._type"],
        "single_key"
    )
    case_num += 1
    
    # PredicateType
    test_cases[f"top_level_{case_num:03d}"] = generate_test_case(
        f"top_level_{case_num:03d}",
        "Verify the attestation has predicateType 'https://slsa.dev/provenance/v0.2'.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType != "https://slsa.dev/provenance/v0.2"
    result := sprintf("Attestation has incorrect predicateType: %s", [attestation.statement.predicateType])
}""",
        ["attestation.statement.predicateType"],
        "single_key"
    )
    case_num += 1
    
    # Subject - single key
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify the attestation has at least one subject image.",
        """deny contains result if {
    some attestation in input.attestations
    count(attestation.statement.subject) == 0
    result := "Attestation has no subject images"
}""",
        ["attestation.statement.subject"],
        "single_key"
    )
    case_num += 1
    
    # Subject - compound (all subjects have name)
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify all subject images in the attestation have a name.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    not subject.name
    result := "Subject image does not have a name"
}""",
        ["attestation.statement.subject", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # Subject - compound (all subjects have digest)
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify all subject images in the attestation have a digest.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    not subject.digest
    result := sprintf("Subject image %s does not have a digest", [subject.name])
}""",
        ["attestation.statement.subject", "subject.digest", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # Subject - compound (all subjects have sha256)
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify all subject images in the attestation have a SHA256 digest.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    not subject.digest.sha256
    result := sprintf("Subject image %s does not have SHA256 digest", [subject.name])
}""",
        ["attestation.statement.subject", "subject.digest.sha256", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # Subject - single key (specific subject name)
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify the attestation has a subject image with name containing 'quay.io'.",
        """deny contains result if {
    some attestation in input.attestations
    subject_names := {s.name | some s in attestation.statement.subject}
    not any([contains(name, "quay.io") | some name in subject_names])
    result := "No subject image contains quay.io"
}""",
        ["attestation.statement.subject", "subject.name"],
        "single_key"
    )
    case_num += 1
    
    # ============================================================================
    # METADATA FIELDS
    # ============================================================================
    
    # Build finished timestamp - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build finished timestamp exists in the attestation metadata.",
        """deny contains result if {
    some attestation in input.attestations
    not attestation.statement.predicate.metadata.buildFinishedOn
    result := "Attestation does not have buildFinishedOn timestamp"
}""",
        ["attestation.statement.predicate.metadata.buildFinishedOn"],
        "single_key"
    )
    case_num += 1
    
    # Build started timestamp - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build started timestamp exists in the attestation metadata.",
        """deny contains result if {
    some attestation in input.attestations
    not attestation.statement.predicate.metadata.buildStartedOn
    result := "Attestation does not have buildStartedOn timestamp"
}""",
        ["attestation.statement.predicate.metadata.buildStartedOn"],
        "single_key"
    )
    case_num += 1
    
    # Build finished after started - compound
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build finished after it started.",
        """deny contains result if {
    some attestation in input.attestations
    started := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildStartedOn)
    finished := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildFinishedOn)
    finished <= started
    result := "Build finished before or at the same time as it started"
}""",
        ["attestation.statement.predicate.metadata.buildStartedOn", "attestation.statement.predicate.metadata.buildFinishedOn"],
        "compound"
    )
    case_num += 1
    
    # Completeness - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build metadata has a completeness field.",
        """deny contains result if {
    some attestation in input.attestations
    not attestation.statement.predicate.metadata.completeness
    result := "Attestation does not have completeness metadata"
}""",
        ["attestation.statement.predicate.metadata.completeness"],
        "single_key"
    )
    case_num += 1
    
    # Completeness environment - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build completeness indicates environment is complete.",
        """deny contains result if {
    some attestation in input.attestations
    completeness := attestation.statement.predicate.metadata.completeness
    completeness.environment != true
    result := "Build completeness indicates environment is not complete"
}""",
        ["attestation.statement.predicate.metadata.completeness.environment"],
        "single_key"
    )
    case_num += 1
    
    # Completeness materials - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build completeness indicates materials are complete.",
        """deny contains result if {
    some attestation in input.attestations
    completeness := attestation.statement.predicate.metadata.completeness
    completeness.materials != true
    result := "Build completeness indicates materials are not complete"
}""",
        ["attestation.statement.predicate.metadata.completeness.materials"],
        "single_key"
    )
    case_num += 1
    
    # Completeness parameters - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build completeness indicates parameters are complete.",
        """deny contains result if {
    some attestation in input.attestations
    completeness := attestation.statement.predicate.metadata.completeness
    completeness.parameters != true
    result := "Build completeness indicates parameters are not complete"
}""",
        ["attestation.statement.predicate.metadata.completeness.parameters"],
        "single_key"
    )
    case_num += 1
    
    # Reproducible - single key
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build is marked as reproducible.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicate.metadata.reproducible != true
    result := "Build is not marked as reproducible"
}""",
        ["attestation.statement.predicate.metadata.reproducible"],
        "single_key"
    )
    case_num += 1
    
    # ============================================================================
    # MATERIALS FIELDS
    # ============================================================================
    
    # Materials exist - single key
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify the attestation has a materials section.",
        """deny contains result if {
    some attestation in input.attestations
    not attestation.statement.predicate.materials
    result := "Attestation does not have materials section"
}""",
        ["attestation.statement.predicate.materials"],
        "single_key"
    )
    case_num += 1
    
    # Materials not empty - single key
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify the attestation has at least one material.",
        """deny contains result if {
    some attestation in input.attestations
    count(attestation.statement.predicate.materials) == 0
    result := "Attestation has no materials"
}""",
        ["attestation.statement.predicate.materials"],
        "single_key"
    )
    case_num += 1
    
    # All materials have URI - compound
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials in the attestation have a URI.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    not material.uri
    result := "Material does not have a URI"
}""",
        ["attestation.statement.predicate.materials", "material.uri"],
        "compound"
    )
    case_num += 1
    
    # All materials have digest - compound
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials in the attestation have a digest.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    not material.digest
    result := sprintf("Material %s does not have a digest", [material.uri])
}""",
        ["attestation.statement.predicate.materials", "material.digest", "material.uri"],
        "compound"
    )
    case_num += 1
    
    # All materials have sha256 - compound
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials in the attestation have a SHA256 digest.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    not material.digest.sha256
    result := sprintf("Material %s does not have SHA256 digest", [material.uri])
}""",
        ["attestation.statement.predicate.materials", "material.digest.sha256", "material.uri"],
        "compound"
    )
    case_num += 1
    
    # Materials with sha1 have git URI - compound
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials with SHA1 digest have a git URI.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    material.digest.sha1
    not startswith(material.uri, "git+")
    result := sprintf("Material with SHA1 digest has non-git URI: %s", [material.uri])
}""",
        ["attestation.statement.predicate.materials", "material.digest.sha1", "material.uri"],
        "compound"
    )
    case_num += 1
    
    # Materials sha1 format - compound
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials with SHA1 digest have valid 40-character hex format.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    commit := material.digest.sha1
    commit
    not regex.match(`^[a-f0-9]{40}$`, commit)
    result := sprintf("Material SHA1 digest %s is not valid format", [commit])
}""",
        ["attestation.statement.predicate.materials", "material.digest.sha1"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # TASK FIELDS - Additional coverage
    # ============================================================================
    
    # Task configSource entryPoint - single key
    test_cases[f"task_{case_num:03d}"] = generate_test_case(
        f"task_{case_num:03d}",
        "Verify the build task configSource has an entryPoint.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    not task.invocation.configSource.entryPoint
    result := "Build task configSource does not have entryPoint"
}""",
        ["task.name", "task.invocation.configSource.entryPoint"],
        "single_key"
    )
    case_num += 1
    
    # All tasks have configSource entryPoint - compound
    test_cases[f"task_{case_num:03d}"] = generate_test_case(
        f"task_{case_num:03d}",
        "Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    not task.invocation.configSource.entryPoint
    result := sprintf("Task %s configSource does not have entryPoint", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.configSource.entryPoint", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Task ref params - single key
    test_cases[f"task_{case_num:03d}"] = generate_test_case(
        f"task_{case_num:03d}",
        "Verify the build task reference has params.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    not task.ref.params
    result := "Build task reference does not have params"
}""",
        ["task.name", "task.ref.params"],
        "single_key"
    )
    case_num += 1
    
    # All tasks have ref params - compound
    test_cases[f"task_{case_num:03d}"] = generate_test_case(
        f"task_{case_num:03d}",
        "Verify all tasks in the PipelineRun attestation have reference params.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    not task.ref.params
    result := sprintf("Task %s reference does not have params", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.ref.params", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # STEP FIELDS
    # ============================================================================
    
    # Step annotations - single key
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify the build task has at least one step with annotations.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    some step in task.steps
    not step.annotations
    result := "Build task has step without annotations"
}""",
        ["task.name", "task.steps", "step.annotations"],
        "single_key"
    )
    case_num += 1
    
    # All steps have annotations - compound
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have annotations.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    not step.annotations
    result := sprintf("Task %s has step without annotations", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.annotations", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Step arguments - single key
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify the build task has at least one step with arguments.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    some step in task.steps
    not step.arguments
    result := "Build task has step without arguments"
}""",
        ["task.name", "task.steps", "step.arguments"],
        "single_key"
    )
    case_num += 1
    
    # All steps have arguments - compound
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have arguments.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    not step.arguments
    result := sprintf("Task %s has step without arguments", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.arguments", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Step environment container - single key
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify the build task has at least one step with environment container set.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    some step in task.steps
    not step.environment.container
    result := "Build task has step without environment container"
}""",
        ["task.name", "task.steps", "step.environment.container"],
        "single_key"
    )
    case_num += 1
    
    # All steps have container - compound
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have environment container set.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    not step.environment.container
    result := sprintf("Task %s has step without environment container", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.container", "task.name"],
        "compound"
    )
    case_num += 1
    
    # All steps have image - compound (already have some, but adding more variations)
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have environment image with oci:// prefix.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    image := step.environment.image
    image
    not startswith(image, "oci://")
    result := sprintf("Task %s has step with image not using oci:// prefix: %s", [task.name, image])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.image", "task.name"],
        "compound"
    )
    case_num += 1
    
    # All steps have image with digest - compound
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have environment image with digest.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    image := step.environment.image
    image
    not contains(image, "@sha256:")
    result := sprintf("Task %s has step with image without digest: %s", [task.name, image])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.image", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # SLSA v1.0 FIELDS
    # ============================================================================
    
    # BuildType - single key
    test_cases[f"slsa_v1_{case_num:03d}"] = generate_test_case(
        f"slsa_v1_{case_num:03d}",
        "Verify the attestation has buildDefinition with buildType 'https://tekton.dev/chains/v2/slsa-tekton'.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    build_type := attestation.statement.predicate.buildDefinition.buildType
    build_type != "https://tekton.dev/chains/v2/slsa-tekton"
    result := sprintf("Attestation has incorrect buildType: %s", [build_type])
}""",
        ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.buildType"],
        "single_key"
    )
    case_num += 1
    
    # ExternalParameters - single key
    test_cases[f"slsa_v1_{case_num:03d}"] = generate_test_case(
        f"slsa_v1_{case_num:03d}",
        "Verify the SLSA v1.0 attestation has externalParameters.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.externalParameters
    result := "SLSA v1.0 attestation does not have externalParameters"
}""",
        ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.externalParameters"],
        "single_key"
    )
    case_num += 1
    
    # InternalParameters - single key
    test_cases[f"slsa_v1_{case_num:03d}"] = generate_test_case(
        f"slsa_v1_{case_num:03d}",
        "Verify the SLSA v1.0 attestation has internalParameters.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.internalParameters
    result := "SLSA v1.0 attestation does not have internalParameters"
}""",
        ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.internalParameters"],
        "single_key"
    )
    case_num += 1
    
    # RunDetails metadata - single key
    test_cases[f"slsa_v1_{case_num:03d}"] = generate_test_case(
        f"slsa_v1_{case_num:03d}",
        "Verify the SLSA v1.0 attestation has runDetails with metadata.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.runDetails.metadata
    result := "SLSA v1.0 attestation does not have runDetails metadata"
}""",
        ["attestation.statement.predicateType", "attestation.statement.predicate.runDetails.metadata"],
        "single_key"
    )
    case_num += 1
    
    # ExternalParameters runSpec - single key
    test_cases[f"slsa_v1_{case_num:03d}"] = generate_test_case(
        f"slsa_v1_{case_num:03d}",
        "Verify the SLSA v1.0 attestation externalParameters has runSpec.",
        """deny contains result if {
    some attestation in input.attestations
    attestation.statement.predicateType == "https://slsa.dev/provenance/v1"
    not attestation.statement.predicate.buildDefinition.externalParameters.runSpec
    result := "SLSA v1.0 attestation externalParameters does not have runSpec"
}""",
        ["attestation.statement.predicateType", "attestation.statement.predicate.buildDefinition.externalParameters.runSpec"],
        "single_key"
    )
    case_num += 1
    
    # ============================================================================
    # ADDITIONAL TASK PARAMETER VARIATIONS
    # ============================================================================
    
    # More parameter checks for different tasks
    task_params = [
        ("git-clone", "url", "Git repository URL"),
        ("git-clone", "revision", "Git revision"),
        ("git-clone", "refspec", "Git refspec"),
        ("git-clone", "depth", "Git clone depth"),
        ("git-clone", "submodules", "Git submodules"),
        ("prefetch-dependencies", "input", "Prefetch input"),
        ("prefetch-dependencies", "ociStorage", "OCI storage location"),
        ("prefetch-dependencies", "sbom-type", "SBOM type"),
        ("build", "image-url", "Image URL"),
        ("build", "rebuild", "Rebuild flag"),
    ]
    
    for task_name, param_name, description in task_params[:5]:  # Add 5 more
        test_cases[f"task_param_{case_num:03d}"] = generate_test_case(
            f"task_param_{case_num:03d}",
            f"Verify the {task_name} task has the {param_name} parameter set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "{task_name}"
    not task.invocation.parameters.{param_name}
    result := "{task_name} task does not have {param_name} parameter"
}}""",
            ["task.name", f"task.invocation.parameters.{param_name}"],
            "single_key"
        )
        case_num += 1
    
    # ============================================================================
    # ADDITIONAL RESULT VARIATIONS
    # ============================================================================
    
    result_names = [
        ("git-clone", "commit", "Git commit SHA"),
        ("git-clone", "url", "Git repository URL"),
        ("git-clone", "short-commit", "Short commit SHA"),
        ("git-clone", "commit-timestamp", "Commit timestamp"),
        ("build", "IMAGE_URL", "Image URL"),
        ("build", "IMAGE_DIGEST", "Image digest"),
    ]
    
    for task_name, result_name, description in result_names[:4]:  # Add 4 more
        test_cases[f"task_result_{case_num:03d}"] = generate_test_case(
            f"task_result_{case_num:03d}",
            f"Verify the {task_name} task produced a result named '{result_name}'.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "{task_name}"
    not "{result_name}" in {{r.name | some r in task.results}}
    result := "{task_name} task did not produce {result_name} result"
}}""",
            ["task.name", "task.results"],
            "single_key"
        )
        case_num += 1
    
    # ============================================================================
    # ADDITIONAL ANNOTATION/LABEL VARIATIONS
    # ============================================================================
    
    annotation_keys = [
        "pipelinesascode.tekton.dev/state",
        "pipelinesascode.tekton.dev/branch",
        "pipelinesascode.tekton.dev/event-type",
        "pipelinesascode.tekton.dev/git-provider",
        "pipelinesascode.tekton.dev/repo-url",
    ]
    
    for ann_key in annotation_keys[:3]:  # Add 3 more
        key_short = ann_key.split("/")[-1]
        test_cases[f"annotation_{case_num:03d}"] = generate_test_case(
            f"annotation_{case_num:03d}",
            f"Verify all tasks in the PipelineRun attestation have the annotation '{ann_key}' set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    annotations := task.invocation.environment.annotations
    not annotations["{ann_key}"]
    result := sprintf("Task %s does not have annotation {ann_key}", [task.name])
}}""",
            ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.annotations", "task.name"],
            "compound"
        )
        case_num += 1
    
    label_keys = [
        "tekton.dev/pipelineRunUID",
        "appstudio.openshift.io/application",
        "appstudio.openshift.io/component",
    ]
    
    for label_key in label_keys[:2]:  # Add 2 more
        test_cases[f"label_{case_num:03d}"] = generate_test_case(
            f"label_{case_num:03d}",
            f"Verify all tasks in the PipelineRun attestation have the label '{label_key}' set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    labels := task.invocation.environment.labels
    not labels["{label_key}"]
    result := sprintf("Task %s does not have label {label_key}", [task.name])
}}""",
            ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.labels", "task.name"],
            "compound"
        )
        case_num += 1
    
    # ============================================================================
    # COMPLEX COMPOUND CASES
    # ============================================================================
    
    # Multiple conditions - tasks with both status and results
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that succeeded have at least one result.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status == "Succeeded"
    count(task.results) == 0
    result := sprintf("Task %s succeeded but has no results", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.status", "task.results", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Multiple conditions - tasks with bundle and digest
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks with bundle references have both bundle and digest.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    bundle := task.ref.bundle
    bundle
    not contains(bundle, "@sha256:")
    not contains(bundle, "@sha1:")
    result := sprintf("Task %s bundle %s does not have digest", [task.name, bundle])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.ref.bundle", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Multiple conditions - tasks with parameters and results
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that have an 'image-url' parameter produced an IMAGE_URL result.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.invocation.parameters["image-url"]
    not "IMAGE_URL" in {r.name | some r in task.results}
    result := sprintf("Task %s has image-url parameter but no IMAGE_URL result", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.parameters", "task.results", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Multiple conditions - tasks with annotations and labels
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks have both annotations and labels.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    not task.invocation.environment.annotations
    not task.invocation.environment.labels
    result := sprintf("Task %s is missing annotations or labels", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.annotations", "task.invocation.environment.labels", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Multiple conditions - tasks with timestamps and status
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that have a status also have both started and finished timestamps.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status
    (not task.startedOn or not task.finishedOn)
    result := sprintf("Task %s has status but missing timestamps", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.status", "task.startedOn", "task.finishedOn", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # EDGE CASES AND VALIDATION
    # ============================================================================
    
    # Empty arrays
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify the attestation has at least one task.",
        """deny contains result if {
    some attestation in input.attestations
    count(attestation.statement.predicate.buildConfig.tasks) == 0
    result := "Attestation has no tasks"
}""",
        ["attestation.statement.predicate.buildConfig.tasks"],
        "single_key"
    )
    case_num += 1
    
    # Empty subject
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify the attestation has at least one subject.",
        """deny contains result if {
    some attestation in input.attestations
    count(attestation.statement.subject) == 0
    result := "Attestation has no subject images"
}""",
        ["attestation.statement.subject"],
        "single_key"
    )
    case_num += 1
    
    # Empty materials
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify the attestation has at least one material.",
        """deny contains result if {
    some attestation in input.attestations
    count(attestation.statement.predicate.materials) == 0
    result := "Attestation has no materials"
}""",
        ["attestation.statement.predicate.materials"],
        "single_key"
    )
    case_num += 1
    
    # Subject name format validation
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify all subject images have names that are not empty.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    subject.name == ""
    result := "Subject image has empty name"
}""",
        ["attestation.statement.subject", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # Material URI format validation
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify all materials have URIs that are not empty.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    material.uri == ""
    result := "Material has empty URI"
}""",
        ["attestation.statement.predicate.materials", "material.uri"],
        "compound"
    )
    case_num += 1
    
    # Task name uniqueness (already have one, but add another variation)
    test_cases[f"edge_{case_num:03d}"] = generate_test_case(
        f"edge_{case_num:03d}",
        "Verify no two tasks in the PipelineRun attestation have the same name.",
        """deny contains result if {
    some attestation in input.attestations
    task_names := {task.name | some task in attestation.statement.predicate.buildConfig.tasks}
    all_task_names := [task.name | some task in attestation.statement.predicate.buildConfig.tasks]
    count(task_names) != count(all_task_names)
    result := "Tasks have duplicate names"
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE TASK PARAMETER VARIATIONS
    # ============================================================================
    
    # Additional parameter checks
    more_params = [
        ("prefetch-dependencies", "log-level", "Log level"),
        ("prefetch-dependencies", "config-file-content", "Config file content"),
        ("prefetch-dependencies", "dev-package-managers", "Dev package managers"),
        ("build", "skip-checks", "Skip checks flag"),
        ("test", "test-command", "Test command"),
    ]
    
    for task_name, param_name, description in more_params:
        test_cases[f"task_param_{case_num:03d}"] = generate_test_case(
            f"task_param_{case_num:03d}",
            f"Verify the {task_name} task has the {param_name} parameter set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "{task_name}"
    not task.invocation.parameters.{param_name}
    result := "{task_name} task does not have {param_name} parameter"
}}""",
            ["task.name", f"task.invocation.parameters.{param_name}"],
            "single_key"
        )
        case_num += 1
    
    # All tasks with specific parameter pattern - compound
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that have a 'log-level' parameter have it set to 'info' or 'debug'.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    log_level := task.invocation.parameters["log-level"]
    log_level
    not log_level in {"info", "debug", "warn", "error"}
    result := sprintf("Task %s has invalid log-level: %s", [task.name, log_level])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.parameters", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE RESULT VARIATIONS
    # ============================================================================
    
    more_results = [
        ("git-clone", "CHAINS-GIT_COMMIT", "Git commit from chains"),
        ("git-clone", "CHAINS-GIT_URL", "Git URL from chains"),
        ("prefetch-dependencies", "SOURCE_ARTIFACT", "Source artifact"),
    ]
    
    for task_name, result_name, description in more_results:
        test_cases[f"task_result_{case_num:03d}"] = generate_test_case(
            f"task_result_{case_num:03d}",
            f"Verify the {task_name} task produced a result named '{result_name}'.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "{task_name}"
    not "{result_name}" in {{r.name | some r in task.results}}
    result := "{task_name} task did not produce {result_name} result"
}}""",
            ["task.name", "task.results"],
            "single_key"
        )
        case_num += 1
    
    # All tasks with results have non-empty values - compound
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that have results have at least one result with a non-empty value.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    count(task.results) > 0
    all_empty := {r.name | some r in task.results; r.value == ""}
    count(all_empty) == count(task.results)
    result := sprintf("Task %s has all empty results", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.results", "task.name", "result.value"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE ANNOTATION VARIATIONS
    # ============================================================================
    
    more_annotations = [
        "pipelinesascode.tekton.dev/max-keep-runs",
        "pipelinesascode.tekton.dev/cancel-in-progress",
        "pipelinesascode.tekton.dev/git-auth-secret",
        "pipelinesascode.tekton.dev/installation-id",
        "pipelinesascode.tekton.dev/log-url",
        "pipelinesascode.tekton.dev/original-prname",
        "pipelinesascode.tekton.dev/pipeline",
        "pipelinesascode.tekton.dev/repository",
        "pipelinesascode.tekton.dev/sender",
        "pipelinesascode.tekton.dev/sha",
        "pipelinesascode.tekton.dev/sha-title",
        "pipelinesascode.tekton.dev/sha-url",
        "pipelinesascode.tekton.dev/source-branch",
        "pipelinesascode.tekton.dev/source-repo-url",
        "pipelinesascode.tekton.dev/url-org",
        "pipelinesascode.tekton.dev/url-repository",
        "results.tekton.dev/recordSummaryAnnotations",
    ]
    
    for ann_key in more_annotations[:10]:  # Add 10 more
        key_short = ann_key.split("/")[-1]
        test_cases[f"annotation_{case_num:03d}"] = generate_test_case(
            f"annotation_{case_num:03d}",
            f"Verify all tasks in the PipelineRun attestation have the annotation '{ann_key}' set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    annotations := task.invocation.environment.annotations
    not annotations["{ann_key}"]
    result := sprintf("Task %s does not have annotation {ann_key}", [task.name])
}}""",
            ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.annotations", "task.name"],
            "compound"
        )
        case_num += 1
    
    # ============================================================================
    # MORE LABEL VARIATIONS
    # ============================================================================
    
    more_labels = [
        "tekton.dev/pipelineRunUID",
        "appstudio.openshift.io/application",
        "appstudio.openshift.io/component",
        "pipelines.appstudio.openshift.io/type",
    ]
    
    for label_key in more_labels[:3]:  # Add 3 more
        test_cases[f"label_{case_num:03d}"] = generate_test_case(
            f"label_{case_num:03d}",
            f"Verify all tasks in the PipelineRun attestation have the label '{label_key}' set.",
            f"""deny contains result if {{
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    labels := task.invocation.environment.labels
    not labels["{label_key}"]
    result := sprintf("Task %s does not have label {label_key}", [task.name])
}}""",
            ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.labels", "task.name"],
            "compound"
        )
        case_num += 1
    
    # ============================================================================
    # MORE STEP VARIATIONS
    # ============================================================================
    
    # Step entryPoint not empty when set
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks that have entryPoint have a non-empty entryPoint.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    step.entryPoint == ""
    result := sprintf("Task %s has step with empty entryPoint", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.entryPoint", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Step arguments not empty when set
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks that have arguments have at least one argument.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    step.arguments
    count(step.arguments) == 0
    result := sprintf("Task %s has step with empty arguments array", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.arguments", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Step environment image format
    test_cases[f"step_{case_num:03d}"] = generate_test_case(
        f"step_{case_num:03d}",
        "Verify all steps in all tasks have environment image in valid format.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    some step in task.steps
    image := step.environment.image
    image
    not startswith(image, "oci://")
    not startswith(image, "docker://")
    result := sprintf("Task %s has step with invalid image format: %s", [task.name, image])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.steps", "step.environment.image", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE MATERIAL VARIATIONS
    # ============================================================================
    
    # Materials with oci:// URI have sha256
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials with oci:// URI have SHA256 digest.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    startswith(material.uri, "oci://")
    not material.digest.sha256
    result := sprintf("Material with oci:// URI %s does not have SHA256 digest", [material.uri])
}""",
        ["attestation.statement.predicate.materials", "material.uri", "material.digest.sha256"],
        "compound"
    )
    case_num += 1
    
    # Materials with quay.io URI
    test_cases[f"materials_{case_num:03d}"] = generate_test_case(
        f"materials_{case_num:03d}",
        "Verify all materials with quay.io URI have SHA256 digest.",
        """deny contains result if {
    some attestation in input.attestations
    some material in attestation.statement.predicate.materials
    contains(material.uri, "quay.io")
    not material.digest.sha256
    result := sprintf("Material with quay.io URI %s does not have SHA256 digest", [material.uri])
}""",
        ["attestation.statement.predicate.materials", "material.uri", "material.digest.sha256"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE SUBJECT VARIATIONS
    # ============================================================================
    
    # Subject name format
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify all subject images have names that contain a registry.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    name := subject.name
    name
    not contains(name, ".")
    not contains(name, "/")
    result := sprintf("Subject image name %s does not appear to be a valid image reference", [name])
}""",
        ["attestation.statement.subject", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # Subject digest format
    test_cases[f"subject_{case_num:03d}"] = generate_test_case(
        f"subject_{case_num:03d}",
        "Verify all subject images have SHA256 digests in valid format.",
        """deny contains result if {
    some attestation in input.attestations
    some subject in attestation.statement.subject
    digest := subject.digest.sha256
    digest
    not regex.match(`^[a-f0-9]{64}$`, digest)
    result := sprintf("Subject image %s has invalid SHA256 digest format", [subject.name])
}""",
        ["attestation.statement.subject", "subject.digest.sha256", "subject.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE METADATA VARIATIONS
    # ============================================================================
    
    # Metadata completeness all true
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build completeness indicates all aspects are complete.",
        """deny contains result if {
    some attestation in input.attestations
    completeness := attestation.statement.predicate.metadata.completeness
    (completeness.environment != true or completeness.materials != true or completeness.parameters != true)
    result := "Build completeness indicates some aspects are not complete"
}""",
        ["attestation.statement.predicate.metadata.completeness"],
        "compound"
    )
    case_num += 1
    
    # Build duration reasonable
    test_cases[f"metadata_{case_num:03d}"] = generate_test_case(
        f"metadata_{case_num:03d}",
        "Verify the build completed within 24 hours of starting.",
        """deny contains result if {
    some attestation in input.attestations
    started := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildStartedOn)
    finished := time.parse_rfc3339_ns(attestation.statement.predicate.metadata.buildFinishedOn)
    duration_hours := (finished - started) / 3600000000000
    duration_hours > 24
    result := sprintf("Build took %d hours, exceeds 24 hour limit", [duration_hours])
}""",
        ["attestation.statement.predicate.metadata.buildStartedOn", "attestation.statement.predicate.metadata.buildFinishedOn"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # MORE COMPLEX COMPOUND CASES
    # ============================================================================
    
    # Tasks with specific name pattern
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks with names ending in '-oci-ta' have bundle references.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    endswith(task.name, "-oci-ta")
    not task.ref.bundle
    result := sprintf("Task %s ending in -oci-ta does not have bundle reference", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.name", "task.ref.bundle"],
        "compound"
    )
    case_num += 1
    
    # Tasks with results matching parameter
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks that have an 'output-image' parameter produced an IMAGE_URL result with matching value.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    output_image := task.invocation.parameters["output-image"]
    output_image
    image_url_result := {r.value | some r in task.results; r.name == "IMAGE_URL"}
    not output_image in image_url_result
    result := sprintf("Task %s output-image parameter does not match IMAGE_URL result", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.parameters", "task.results", "task.name"],
        "compound"
    )
    case_num += 1
    
    # Tasks with annotations matching labels
    test_cases[f"compound_{case_num:03d}"] = generate_test_case(
        f"compound_{case_num:03d}",
        "Verify all tasks have matching pipeline and pipelineRun in both annotations and labels.",
        """deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    annotations := task.invocation.environment.annotations
    labels := task.invocation.environment.labels
    pipeline_ann := annotations["tekton.dev/pipeline"]
    pipeline_label := labels["tekton.dev/pipeline"]
    pipeline_ann
    pipeline_label
    pipeline_ann != pipeline_label
    result := sprintf("Task %s has mismatched pipeline in annotations and labels", [task.name])
}""",
        ["attestation.statement.predicate.buildConfig.tasks", "task.invocation.environment.annotations", "task.invocation.environment.labels", "task.name"],
        "compound"
    )
    case_num += 1
    
    # ============================================================================
    # ADD MORE FROM EXISTING 100 TEST CASES
    # ============================================================================
    
    # Load existing test cases and add them
    try:
        with open("100_test_cases.json") as f:
            existing = json.load(f)
            existing_cases = existing.get("test_cases", {})
            
            # Add all existing cases
            for key, value in existing_cases.items():
                if key not in test_cases:  # Avoid duplicates
                    test_cases[key] = value
    except FileNotFoundError:
        pass
    
    return test_cases

def main():
    """Generate comprehensive test cases."""
    test_cases = generate_all_test_cases()
    
    # Count types
    single_key = sum(1 for v in test_cases.values() if v.get("type") == "single_key")
    compound = sum(1 for v in test_cases.values() if v.get("type") == "compound")
    
    output = {
        "metadata": {
            "total_test_cases": len(test_cases),
            "single_key_cases": single_key,
            "compound_cases": compound,
            "rules": [
                "ALL rules start with: some attestation in input.attestations",
                "NEVER reuse 'result' variable - reserved for deny output",
                "Use descriptive variable names for loops (task_result, r, step, material, subject, etc.)"
            ]
        },
        "test_cases": test_cases
    }
    
    with open("../data/comprehensive_test_cases.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated {len(test_cases)} test cases")
    print(f"  Single key: {single_key}")
    print(f"  Compound: {compound}")

if __name__ == "__main__":
    main()
