# File Editing Training Data

This document describes the training data generated for teaching the model how to edit existing Rego policy files by adding new rules.

## Two-Track Training Approach

We recommend a two-track training approach:

### Track A: Generic Tool Usage (Foundation)
**Script:** `generate_generic_tool_usage_training.py`

Teaches pure tool usage behavior:
- How to read files with tools
- How to modify content
- How to write files back
- **WITHOUT** domain-specific reasoning
- **WITHOUT** Rego/attestation knowledge
- Just procedural correctness

This creates the behavioral scaffold before adding domain knowledge.

### Track B: Domain-Specific File Editing
**Scripts:** `generate_file_editing_training.py` or `generate_file_editing_training_with_tools.py`

Teaches domain-specific editing:
- Rego policy structure
- Attestation format knowledge
- Rule placement conventions
- Domain-specific patterns

**Training Order:**
1. First train on Track A (generic tool usage)
2. Then fine-tune on Track B (domain-specific)

This layered approach teaches the model tool usage patterns first, then adds domain expertise.

## Overview

The file editing training data teaches the model to:
1. Add new rules to existing policy files
2. Maintain proper file structure (package, imports, metadata)
3. Place new rules in the correct location (after existing deny rules, before helper rules)
4. Preserve all existing rules and formatting

## Two Approaches: With and Without Tools

There are two variants of file editing training:

### 1. Direct Content Generation (Default)

**Script:** `generate_file_editing_training.py`

This approach teaches the model to:
- Understand file paths and content
- Generate the complete updated file content directly
- **Does NOT** teach file I/O operations

**Use this when:**
- Your model will generate file content that you'll save manually
- You're using the model in a context where it outputs text that you copy/paste
- You don't have file I/O tools available

### 2. Tool-Based File Operations

**Script:** `generate_file_editing_training_with_tools.py`

This approach teaches the model to:
- Use `read_file` tool to read existing files
- Edit the file content
- Use `write_file` tool to save updated files
- Follow a read → edit → write workflow

**Use this when:**
- Your model has access to file I/O tools (read_file, write_file)
- You want the model to autonomously edit files
- You're building a coding assistant that can modify files directly

**Tool Format:**
The tool-based training uses XML-style tool calls:
```
<tool_call>
<function=read_file>
<parameter=path>
policy/release/tasks/tasks.rego
</parameter>
</function>
</tool_call>
```

## Why File Editing Training?

While the base training teaches the model to generate standalone rules, real-world policy development often involves:
- Adding new rules to existing policy files
- Maintaining consistency with existing code style
- Understanding where to place new rules in the file structure

## Training Example Format

Each training example follows this structure:

**System Prompt:**
- Includes standard Rego/Enterprise Contract context
- Adds file editing guidelines explaining where to place new rules

**User Prompt:**
- **For real policy files**: Provides the file path (e.g., `policy/release/tasks/tasks.rego`) and the file content
- **For synthetic files**: Shows the complete existing file content
- Provides the new requirement to implement
- Asks for the complete updated file

**Assistant Response:**
- Provides the complete updated file with the new rule added
- Maintains all existing rules and structure
- Places the new rule in the correct location

## Using the Fine-Tuned Model

When you use the fine-tuned model, you should prompt it with similar formats to what it saw during training:

### For Tool-Based Model

**Recommended prompt format:**
```
Add a new rule to the existing Rego policy file at `policy/release/tasks/tasks.rego`.

**New requirement:**
Verify all tasks have status 'Succeeded'.

Use the read_file tool to read the current file, then add the new rule and save it with write_file.
```

**Simplified prompt (model should infer tool usage):**
```
Add a new rule to policy/release/tasks/tasks.rego that verifies all tasks have status 'Succeeded'.
```

The model will automatically use the read → edit → write workflow it learned during training.

### For Direct Content Model

**Recommended prompt format:**
```
Add a new rule to the existing Rego policy file at `policy/release/tasks/tasks.rego`.

**Current file content:**
```rego
[existing file content]
```

**New requirement:**
Verify all tasks have status 'Succeeded'.

Provide the complete updated file with the new rule added in the correct location.
```

### Path-Based Examples

When using real policy files, the training examples emphasize the file path:

```
Add a new rule to the existing Rego policy file at `policy/release/tasks/tasks.rego`.

**Current file content:**
```rego
[existing file content]
```

**New requirement:**
[requirement text]

Provide the complete updated file with the new rule added in the correct location.
```

This teaches the model to work with file paths, which is more realistic for actual development workflows.

## Generating File Editing Training Data

### Track A: Generic Tool Usage (Start Here)

```bash
cd rego-training/scripts/core
python generate_generic_tool_usage_training.py
```

This script:
1. Creates simple file editing examples (text files, configs, etc.)
2. Teaches read → edit → write workflow
3. Focuses on procedural correctness
4. No domain knowledge required
5. Outputs to `data/qwen3-generic-tool-usage-training.jsonl`

**Example types:**
- Line replacement
- Insertion/deletion
- Text replacement
- Append/prepend
- Multiple operations
- Empty file handling
- Whitespace preservation

**System Prompt Style:**
```
Your job is to edit files using tools exactly as the user instructs.
Do not infer missing logic. Do not create domain-specific content.
Only manipulate the text the user describes.
```

**Training Trajectory:**
```
User: "Edit file.txt. Replace line 3 with 'Updated line'"
Assistant: <tool_call read_file>
<tool_response> [file content] </tool_response>
Assistant: "OK, now I will replace line 3."
<tool_call write_file>
<tool_response> File written successfully. </tool_response>
Assistant: "Done."
```

### Option 1: Direct Content Generation (Track B)

```bash
cd rego-training/scripts/core
python generate_file_editing_training.py
```

This script:
1. Uses actual policy files from `policy/` directory (which often have multiple rules)
2. Creates synthetic multi-rule files by combining training rego files
3. Generates examples showing how to add new rules to existing files
4. Outputs to `data/qwen3-file-editing-training.jsonl`

**Training Format:** Model generates complete updated file content directly.

### Option 2: Tool-Based File Operations (Track B)

```bash
cd rego-training/scripts/core
python generate_file_editing_training_with_tools.py
```

This script:
1. Uses the same file sources as Option 1
2. Generates examples that show tool usage (read_file, write_file)
3. Teaches the model to follow a read → edit → write workflow
4. Outputs to `data/qwen3-file-editing-tools-training.jsonl`

**Training Format:** Model learns to use tools to read and write files.

**Note:** For tool-based training to work, your inference system must:
- Provide `read_file` and `write_file` tool definitions (see [TOOL_DEFINITIONS.md](TOOL_DEFINITIONS.md))
- Support tool calling in the model's response format
- Execute tool calls and return results

**Important:** The model learns the tool interface (names, parameters, format) but does NOT learn which binary/executable to use. Tool implementations are provided by your inference system at runtime. See [TOOL_DEFINITIONS.md](TOOL_DEFINITIONS.md) for details.

### How It Works

The script uses three strategies:

1. **Real Policy Files**: Uses actual policy files from `policy/release/`, `policy/task/`, and `policy/pipeline/` directories that contain multiple rules. These provide realistic examples of multi-rule files.

2. **Synthetic Multi-Rule Files**: Combines multiple single-rule training files (from `rego_rules/`) to create synthetic files with 2-3 rules. This expands the training dataset.

3. **Rule Grouping**: Groups files by prefix (e.g., `task_*`, `step_*`) to create related rules that make sense together.

### Example Training Example

**Input (User Prompt) - Path-Based:**
```
Add a new rule to the existing Rego policy file at `policy/release/tasks/tasks.rego`.

**Current file content:**
```rego
package tasks

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: Pipeline run includes at least one task
deny contains result if {
	some att in lib.pipelinerun_attestations
	count(tekton.tasks(att)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}
```

**New requirement:**
Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.
```

**Input (User Prompt) - Content-Based (for synthetic files):**
```
I have an existing Rego policy file. Please add a new rule to it based on this requirement:

**Existing File:**
```rego
package task_023

import rego.v1

# METADATA
# title: Verify the build task configSource has an entryPoint.
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.configSource.entryPoint
	result := "Build task configSource does not have entryPoint"
}
```

**New Requirement:**
Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.
```

**Output (Assistant Response):**
```
Here's the updated file with the new rule added:

```rego
package task_023

import rego.v1

# METADATA
# title: Verify the build task configSource has an entryPoint.
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	task.name == "build"
	not task.invocation.configSource.entryPoint
	result := "Build task configSource does not have entryPoint"
}

# METADATA
# title: Verify all tasks in the PipelineRun attestation have a configSource with entryPoint.
deny contains result if {
	some attestation in input.attestations
	some task in attestation.statement.predicate.buildConfig.tasks
	not task.invocation.configSource.entryPoint
	result := sprintf("Task %s configSource does not have entryPoint", [task.name])
}
```

The new rule has been added after the existing deny rules, maintaining the proper file structure...
```

## Integrating with Training Pipeline

### Recommended Two-Track Approach

**Step 1: Train on Generic Tool Usage (Track A)**

```bash
# Generate generic tool usage training
python scripts/core/generate_generic_tool_usage_training.py

# Fine-tune base model on generic tool usage
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-generic-tool-usage-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-tool-usage-base
```

**Step 2: Fine-tune on Domain-Specific Editing (Track B)**

```bash
# Generate domain-specific file editing training
python scripts/core/generate_file_editing_training_with_tools.py

# Fine-tune the tool-usage model on domain-specific editing
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-file-editing-tools-training.jsonl \
  --model ./qwen3-tool-usage-base \
  --output-dir ./qwen3-rego-file-editing
```

### Alternative: Single-Track Approach

**Step 1: Generate File Editing Training Data**

**Choose one based on your needs:**

**For direct content generation:**
```bash
python scripts/core/generate_file_editing_training.py
```

**For tool-based operations:**
```bash
python scripts/core/generate_file_editing_training_with_tools.py
```

### Step 2: Merge with Other Training Data

**For direct content generation:**
```bash
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-training-data.jsonl \
  --test-data data/qwen3-test-creation-training.jsonl \
  --file-editing-data data/qwen3-file-editing-training.jsonl \
  --output data/qwen3-complete-training.jsonl
```

**For tool-based operations:**
```bash
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-training-data.jsonl \
  --test-data data/qwen3-test-creation-training.jsonl \
  --file-editing-data data/qwen3-file-editing-tools-training.jsonl \
  --output data/qwen3-complete-training.jsonl
```

The merge script will automatically include file editing data if the file exists.

### Step 3: Use in Fine-tuning

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-rego-finetuned
```

## Benefits

1. **Real-world Workflow**: Teaches the model the common workflow of adding rules to existing files
2. **Structure Awareness**: Model learns proper file organization and rule placement
3. **Consistency**: Model maintains existing code style and formatting
4. **Context Preservation**: Model understands how to preserve existing rules and helpers

## Tips

- **File Size**: The script limits examples from policy files to avoid overly large training examples
- **Synthetic Files**: Synthetic multi-rule files are created from related rules (same prefix) for coherence
- **Validation**: Consider validating generated examples to ensure they maintain proper Rego syntax

## Troubleshooting

### No Examples Generated

- Check that `policy/` directory exists and contains `.rego` files
- Verify that `rego_rules/` directory has training files
- Ensure files have proper METADATA blocks with titles

### Too Many Examples

- The script limits examples from policy files to prevent dataset bloat
- Adjust the limits in the script if needed

### File Structure Issues

- The script attempts to preserve package declarations and imports
- Helper rules (starting with `_`) are placed after all deny rules
- If issues occur, check the `combine_files()` function logic
