# Test Cases Coverage Summary

## Overview

**Total Test Cases:** 224
- **Single Key Cases:** 90 (checking one property after filtering by task name)
- **Compound Cases:** 134 (looping over all tasks/materials/subjects, checking multiple properties)

## Field Coverage

### Top-Level Fields (2 keys)
- ✅ `attestation.statement._type` - Statement type validation
- ✅ `attestation.statement.predicateType` - Predicate type validation (v0.2, v1.0)

### Subject Fields (4 keys)
- ✅ `attestation.statement.subject` - Subject array existence and count
- ✅ `subject.name` - Subject image name validation
- ✅ `subject.digest` - Digest object validation
- ✅ `subject.digest.sha256` - SHA256 digest format validation

### Materials Fields (2 keys)
- ✅ `attestation.statement.predicate.materials` - Materials array existence and count
- ✅ `material.uri` - Material URI validation (git+, oci://, quay.io)
- ✅ `material.digest` - Digest object validation
- ✅ `material.digest.sha256` - SHA256 digest format validation
- ✅ `material.digest.sha1` - SHA1 digest format validation (40-char hex, git URI requirement)

### Metadata Fields (8 keys)
- ✅ `attestation.statement.predicate.metadata.buildStartedOn` - Build start timestamp validation
- ✅ `attestation.statement.predicate.metadata.buildFinishedOn` - Build finish timestamp validation
- ✅ `attestation.statement.predicate.metadata.completeness` - Completeness object validation
- ✅ `attestation.statement.predicate.metadata.completeness.environment` - Environment completeness
- ✅ `attestation.statement.predicate.metadata.completeness.materials` - Materials completeness
- ✅ `attestation.statement.predicate.metadata.completeness.parameters` - Parameters completeness
- ✅ `attestation.statement.predicate.metadata.reproducible` - Reproducibility flag

### Task Fields (33 keys)
- ✅ `attestation.statement.predicate.buildConfig.tasks` - Tasks array iteration
- ✅ `task.name` - Task name validation and filtering
- ✅ `task.status` - Task status validation (Succeeded, Failed, etc.)
- ✅ `task.invocation` - Invocation object validation
- ✅ `task.invocation.parameters` - Parameters object validation
- ✅ `task.invocation.parameters.<param_name>` - Specific parameter checks (mode, sslVerify, url, revision, etc.)
- ✅ `task.invocation.configSource` - ConfigSource object validation
- ✅ `task.invocation.configSource.uri` - ConfigSource URI validation
- ✅ `task.invocation.configSource.digest` - ConfigSource digest validation
- ✅ `task.invocation.configSource.digest.sha256` - ConfigSource SHA256 validation
- ✅ `task.invocation.configSource.entryPoint` - ConfigSource entryPoint validation
- ✅ `task.invocation.environment` - Environment object validation
- ✅ `task.invocation.environment.annotations` - Annotations validation (various keys)
- ✅ `task.invocation.environment.labels` - Labels validation (various keys)
- ✅ `task.ref` - Reference object validation
- ✅ `task.ref.name` - Reference name validation
- ✅ `task.ref.kind` - Reference kind validation
- ✅ `task.ref.bundle` - Bundle reference validation (with digest checks)
- ✅ `task.ref.params` - Reference params validation
- ✅ `task.results` - Results array validation
- ✅ `result.name` - Result name validation
- ✅ `result.value` - Result value validation
- ✅ `task.steps` - Steps array validation
- ✅ `task.startedOn` - Task start timestamp validation
- ✅ `task.finishedOn` - Task finish timestamp validation

### Step Fields (7 keys)
- ✅ `task.steps` - Steps array iteration
- ✅ `step.entryPoint` - Step entryPoint validation
- ✅ `step.arguments` - Step arguments validation
- ✅ `step.annotations` - Step annotations validation
- ✅ `step.environment` - Step environment validation
- ✅ `step.environment.image` - Step image validation (oci://, docker://, digest checks)
- ✅ `step.environment.container` - Step container name validation

### SLSA v1.0 Fields (8 keys)
- ✅ `attestation.statement.predicate.buildDefinition` - BuildDefinition object validation
- ✅ `attestation.statement.predicate.buildDefinition.buildType` - BuildType validation
- ✅ `attestation.statement.predicate.buildDefinition.externalParameters` - ExternalParameters validation
- ✅ `attestation.statement.predicate.buildDefinition.externalParameters.runSpec` - RunSpec validation
- ✅ `attestation.statement.predicate.buildDefinition.externalParameters.runSpec.pipelineSpec` - PipelineSpec validation
- ✅ `attestation.statement.predicate.buildDefinition.internalParameters` - InternalParameters validation
- ✅ `attestation.statement.predicate.buildDefinition.internalParameters.labels` - InternalParameters labels
- ✅ `attestation.statement.predicate.buildDefinition.internalParameters.annotations` - InternalParameters annotations
- ✅ `attestation.statement.predicate.runDetails.metadata` - RunDetails metadata validation

## Test Case Patterns

### Single Key Patterns
- Check specific task by name has property
- Check attestation-level property exists
- Check specific parameter value for named task
- Check specific result exists for named task

### Compound Patterns
- Loop over all tasks and check property
- Loop over all materials and check property
- Loop over all subjects and check property
- Loop over all steps and check property
- Multiple condition checks (e.g., status + results)
- Cross-field validation (e.g., parameter + result matching)
- Format validation (timestamps, digests, URIs)
- Uniqueness checks (task names, result names)

## Rules Followed

1. ✅ **ALL rules start with:** `some attestation in input.attestations`
2. ✅ **NEVER reuse 'result' variable** - reserved for deny output
3. ✅ **Use descriptive variable names** for loops:
   - `task_result` for task results
   - `r` for result in result loops
   - `step` for step in step loops
   - `material` for material in material loops
   - `subject` for subject in subject loops
   - `annotation_key`, `annotation_value` for annotation iteration
   - `label_key`, `label_value` for label iteration

## File Location

All test cases are stored in: `comprehensive_test_cases.json`

## Usage

These test cases can be used to:
1. Generate training data for Qwen3 model
2. Validate Rego code generation
3. Test policy rule correctness
4. Document attestation structure navigation patterns
