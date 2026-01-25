# Attestation Structure Training Data

This document maps natural language descriptions to JSON paths in the attestation structure, enabling models to understand how to navigate the attestation data when writing policy rules.

## Input Structure Overview

The input to policy rules follows this structure:
```json
{
  "attestations": [
    {
      "statement": {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
          "buildConfig": {
            "tasks": [...]
          },
          "metadata": {...}
        }
      }
    }
  ]
}
```

## Key Path Mappings

### Top-Level Navigation

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "all attestations" | `input.attestations` | Array of all attestations |
| "each attestation" | `some attestation in input.attestations` | Iterate over attestations |
| "the statement in an attestation" | `attestation.statement` | The in-toto statement object |
| "the predicate type" | `attestation.statement.predicateType` | Type of predicate (e.g., "https://slsa.dev/provenance/v0.2") |
| "the predicate" | `attestation.statement.predicate` | The predicate data containing build information |

### SLSA v0.2 Structure (buildConfig)

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "tasks in the PipelineRun attestation" | `attestation.statement.predicate.buildConfig.tasks` | Array of tasks in SLSA v0.2 format (standard path) |
| "tasks in the PipelineRun attestation (alternative)" | `attestation.statement.predicate.buildDefinition.tasks` | Alternative path that may appear in some attestation formats |
| "each task in the attestation" | `some task in attestation.statement.predicate.buildConfig.tasks` | Iterate over tasks |
| "build metadata" | `attestation.statement.predicate.metadata` | Build metadata (timestamps, completeness) |
| "build finished timestamp" | `attestation.statement.predicate.metadata.buildFinishedOn` | ISO 8601 timestamp when build finished |
| "build started timestamp" | `attestation.statement.predicate.metadata.buildStartedOn` | ISO 8601 timestamp when build started |

### SLSA v1.0 Structure (buildDefinition)

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "tasks in the PipelineRun attestation (v1.0)" | `attestation.statement.predicate.buildDefinition.resolvedDependencies` | Array of dependencies (tasks encoded in base64) |
| "build definition" | `attestation.statement.predicate.buildDefinition` | Build definition in SLSA v1.0 format |
| "build type" | `attestation.statement.predicate.buildDefinition.buildType` | Type of build (e.g., "https://tekton.dev/chains/v2/slsa-tekton") |
| "external parameters" | `attestation.statement.predicate.buildDefinition.externalParameters` | External build parameters |
| "internal parameters" | `attestation.statement.predicate.buildDefinition.internalParameters` | Internal build parameters |
| "run details metadata" | `attestation.statement.predicate.runDetails.metadata` | Run details metadata in SLSA v1.0 |

### Task Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "task name" | `task.name` | Name of the task (pipeline task name in v0.2) |
| "task invocation" | `task.invocation` | Task invocation information |
| "task parameters" | `task.invocation.parameters` | Object with parameter key-value pairs |
| "a specific parameter value" | `task.invocation.parameters.<param_name>` | Value of a specific parameter (e.g., `task.invocation.parameters.mode`) |
| "task config source" | `task.invocation.configSource` | Source configuration for the task |
| "task environment" | `task.invocation.environment` | Environment information (annotations, labels) |
| "task annotations" | `task.invocation.environment.annotations` | Kubernetes annotations for the task |
| "task labels" | `task.invocation.environment.labels` | Kubernetes labels for the task |
| "task reference" | `task.ref` | Reference to the task bundle/definition |
| "task bundle" | `task.ref.bundle` | OCI bundle reference for the task |
| "task results" | `task.results` | Array of task results/outputs |
| "a specific result" | `some result in task.results; result.name == "<name>"` | Find a result by name |
| "result value" | `result.value` | Value of a task result |
| "task steps" | `task.steps` | Array of steps executed in the task |
| "task status" | `task.status` | Status of the task (e.g., "Succeeded", "Failed") |
| "task finished timestamp" | `task.finishedOn` | ISO 8601 timestamp when task finished |
| "task started timestamp" | `task.startedOn` | ISO 8601 timestamp when task started |

### Task Reference Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "task reference name" | `task.ref.name` | Name of the referenced task |
| "task reference kind" | `task.ref.kind` | Kind of reference (e.g., "task") |
| "task reference bundle" | `task.ref.bundle` | OCI bundle reference |
| "task reference params" | `task.ref.params` | Parameters for the task reference |

### Subject Structure (Image References)

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "subject images" | `attestation.statement.subject` | Array of subject images |
| "image name" | `subject.name` | Image reference name |
| "image digest" | `subject.digest` | Image digest object |
| "image SHA256 digest" | `subject.digest.sha256` | SHA256 digest value |

### Materials Structure (Dependencies)

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "build materials" | `attestation.statement.predicate.materials` | Array of build materials/dependencies |
| "material URI" | `material.uri` | URI of the material |
| "material digest" | `material.digest` | Digest of the material |

## Example Mappings

### Example 1: Prefetch Dependencies Task Parameter Check

**Natural Language:**
"Verify the prefetch-dependencies task in the PipelineRun attestation was not invoked with the 'permissive' mode parameter."

**JSON Path Navigation:**
1. Loop over all attestations: `some attestation in input.attestations`
2. Access tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
3. Check task name: `task.name == "prefetch-dependencies"`
4. Check parameter value: `task.invocation.parameters.mode == "permissive"`

**Rego Code Pattern:**
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
```

### Example 2: Task Status Check

**Natural Language:**
"Verify all tasks in the PipelineRun attestation completed successfully."

**JSON Path Navigation:**
1. Loop over all attestations: `some attestation in input.attestations`
2. Access tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
3. Check status: `task.status != "Succeeded"`

**Rego Code Pattern:**
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status != "Succeeded"
    result := sprintf("Task %s did not succeed", [task.name])
}
```

### Example 3: Task Bundle Reference Check

**Natural Language:**
"Verify that a task named 'build' uses a trusted bundle reference."

**JSON Path Navigation:**
1. Loop over all attestations: `some attestation in input.attestations`
2. Access tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
3. Check task name: `task.name == "build"`
4. Access bundle: `task.ref.bundle`
5. Check if bundle is in trusted list

**Rego Code Pattern:**
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    bundle := task.ref.bundle
    not bundle in trusted_bundles
    result := sprintf("Task %s uses untrusted bundle %s", [task.name, bundle])
}
```

### Example 4: Task Result Check

**Natural Language:**
"Verify that the build task produced a result named 'IMAGE_URL'."

**JSON Path Navigation:**
1. Loop over all attestations: `some attestation in input.attestations`
2. Access tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
3. Check task name: `task.name == "build"`
4. Access results: `some result in task.results`
5. Check result name: `result.name == "IMAGE_URL"`

**Rego Code Pattern:**
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "build"
    not "IMAGE_URL" in {r.name | some r in task.results}
    result := "Build task did not produce IMAGE_URL result"
}
```

### Example 5: Build Timestamp Check

**Natural Language:**
"Verify the build finished within the last 24 hours."

**JSON Path Navigation:**
1. Loop over all attestations: `some attestation in input.attestations`
2. Access metadata: `attestation.statement.predicate.metadata.buildFinishedOn`
3. Parse timestamp and compare with current time

**Rego Code Pattern:**
```rego
deny contains result if {
    some attestation in input.attestations
    finished_on := attestation.statement.predicate.metadata.buildFinishedOn
    # Parse timestamp and check if older than 24 hours
    # (implementation details depend on time library)
}
```

## Common Patterns

### Pattern 1: Finding a Task by Name
```rego
some task in attestation.statement.predicate.buildConfig.tasks
task.name == "<task-name>"
```

### Pattern 2: Checking a Task Parameter
```rego
task.invocation.parameters.<parameter-name> == "<value>"
```

### Pattern 3: Checking Task Results
```rego
some result in task.results
result.name == "<result-name>"
result.value == "<expected-value>"
```

### Pattern 4: Checking Task Bundle
```rego
bundle := task.ref.bundle
# Then check bundle against trusted list or pattern
```

### Pattern 5: Checking Task Annotations
```rego
some annotation_key, annotation_value in task.invocation.environment.annotations
annotation_key == "<key>"
annotation_value == "<value>"
```

### Pattern 6: Checking Task Labels
```rego
some label_key, label_value in task.invocation.environment.labels
label_key == "<key>"
label_value == "<value>"
```

## Notes

1. **SLSA Version Differences**: The structure differs between SLSA v0.2 and v1.0:
   - v0.2: `predicate.buildConfig.tasks` (standard path)
   - v0.2 (alternative): `predicate.buildDefinition.tasks` (may appear in some formats)
   - v1.0: `predicate.buildDefinition.resolvedDependencies` (tasks are base64-encoded)

2. **Task Name vs Pipeline Task Name**: 
   - In SLSA v0.2: `task.name` is the pipeline task name
   - In SLSA v1.0: Pipeline task name is in `task.metadata.labels["tekton.dev/pipelineTask"]`

3. **Parameters Location**:
   - In SLSA v0.2: `task.invocation.parameters`
   - In SLSA v1.0: May be in `task.spec.params` or `task.invocation.parameters`

4. **Results Location**:
   - In SLSA v0.2: `task.results`
   - In SLSA v1.0: `task.status.results`

5. **Helper Libraries**: The codebase uses helper libraries in `policy/lib/tekton/` that normalize these differences:
   - `tekton.tasks(attestation)` - Returns tasks from either format
   - `tekton.task_name(task)` - Returns task name from either format
   - `tekton.task_params(task)` - Returns parameters from either format
   - `tekton.task_results(task)` - Returns results from either format

## Training Examples

### Example Training Entry

**Input (Natural Language):**
"Verify the prefetch-dependencies task in the PipelineRun attestation was not invoked with the 'permissive' mode parameter."

**Expected Output (JSON Path Navigation):**
```json
{
  "steps": [
    {
      "action": "iterate",
      "path": "input.attestations",
      "variable": "attestation"
    },
    {
      "action": "iterate",
      "path": "attestation.statement.predicate.buildConfig.tasks",
      "variable": "task"
    },
    {
      "action": "filter",
      "path": "task.name",
      "operator": "==",
      "value": "prefetch-dependencies"
    },
    {
      "action": "check",
      "path": "task.invocation.parameters.mode",
      "operator": "==",
      "value": "permissive"
    }
  ],
  "result": "prefetch-dependencies mode is permissive"
}
```

**Expected Rego Code:**
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
```
