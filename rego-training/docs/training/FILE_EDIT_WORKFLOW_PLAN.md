# File Edit Workflow Implementation Plan

Based on `file_edit_workflow.md`, this document outlines the plan to properly implement file editing operations according to the correct workflow.

## Current State Analysis

### What We Have Now

1. **Training Data**:
   - Generic tool usage training (Track A)
   - Rego-specific training (Track B)
   - Tool calls embedded in assistant content (XML format)

2. **Inference Script** (`inference_qwen3_with_tools.py`):
   - Parses tool calls from model output
   - Executes `read_file` and `write_file` tools
   - Has natural language inference fallback
   - Tries to infer operations when model doesn't generate tool calls

3. **Issues**:
   - Model sometimes generates content instead of tool calls
   - Model infers content from training examples
   - Natural language inference is brittle
   - Model may not follow the exact workflow

## Correct Workflow (from file_edit_workflow.md)

### Key Principles

1. **LLM NEVER touches filesystem**
   - LLM only produces tool calls
   - LLM generates new file content as plain text
   - LLM does NOT diff, patch, or verify files

2. **Deterministic Tools Handle Everything**
   - Reading files
   - Writing files
   - Path validation
   - Error handling
   - Safety checks

3. **Workflow Steps**:
   ```
   User Instruction
     ↓
   LLM: Generate read_file tool call
     ↓
   Runtime: Execute read_file (deterministic)
     ↓
   LLM: See file content, generate new content
     ↓
   LLM: Generate write_file tool call with new content
     ↓
   Runtime: Execute write_file (deterministic)
   ```

## Implementation Plan

### Phase 1: Fix Training Data ✅ (Partially Done)

**Status**: In progress

**Tasks**:
- [x] Embed tool calls in assistant content (XML format)
- [x] Add examples for empty file handling
- [x] Add examples for quoted content extraction
- [ ] **Add examples that show FULL file content generation** (not diffs)
- [ ] **Remove any examples that show diff/patch operations**
- [ ] **Emphasize: LLM generates entire new file, not patches**

**Action Items**:
1. Update `generate_generic_tool_usage_training.py`:
   - Ensure all examples show complete file content in `write_file`
   - Add explicit examples: "Generate the entire new file content"
   - Remove any diff/patch language from system prompts

2. Update `generate_file_editing_training_with_tools.py`:
   - Show complete file content generation
   - Emphasize: read → reason → generate full content → write

### Phase 2: Fix Inference Script

**Status**: Needs work

**Current Issues**:
- Natural language inference is too aggressive
- May not follow strict tool-call workflow
- Doesn't enforce "LLM generates full content" pattern

**Tasks**:
- [ ] **Remove or minimize natural language inference**
  - Only use as last resort
  - Prefer model-generated tool calls
  - Log when inference is used (for debugging)

- [ ] **Enforce strict workflow**:
  - Step 1: Model must generate `read_file` tool call
  - Step 2: Execute tool, return content to model
  - Step 3: Model must generate `write_file` with FULL content
  - Step 4: Execute tool, done

- [ ] **Add validation**:
  - Verify model generates tool calls (not just text)
  - Verify `write_file` contains complete file content
  - Warn if content looks like a diff/patch

- [ ] **Improve error handling**:
  - If model doesn't generate tool calls, show clear error
  - Don't silently infer operations
  - Guide user to retry with clearer prompt

### Phase 3: Update System Prompts

**Status**: Needs work

**Current System Prompts**:
- Generic tool usage: Good, but could emphasize "full content generation"
- Rego-specific: May not emphasize workflow correctly

**Tasks**:
- [ ] **Update generic tool usage system prompt**:
  ```
  When editing files:
  1. First, use read_file to get the current file content
  2. Read the content and understand what needs to change
  3. Generate the COMPLETE new file content (not a diff or patch)
  4. Use write_file with the complete new content
  ```

- [ ] **Update Rego-specific system prompt**:
  - Same workflow emphasis
  - Add: "Generate the entire updated file, not just the new rule"

- [ ] **Add workflow examples to prompts**:
  - Show example: read → see content → generate full new content → write

### Phase 4: Create Deterministic Tool Layer

**Status**: Partially done (`inference_simple_file_ops.py` exists)

**Tasks**:
- [x] Create deterministic file operations script
- [ ] **Document when to use deterministic vs model-based**:
  - Deterministic: Simple operations (create, add, replace)
  - Model-based: Complex reasoning (code generation, rule creation)

- [ ] **Consider hybrid approach**:
  - Use deterministic tools for simple file ops
  - Use model for content generation only
  - Combine: Model generates content → Deterministic tool writes it

### Phase 5: Testing & Validation

**Status**: Not started

**Tasks**:
- [ ] **Create test cases**:
  - Simple file operations (create, read, add)
  - Complex operations (edit existing file, add rule)
  - Edge cases (empty files, large files, special characters)

- [ ] **Validate workflow**:
  - Model generates tool calls (not just text)
  - Tool calls are properly formatted
  - Full file content is generated (not diffs)
  - Deterministic tools execute correctly

- [ ] **Performance testing**:
  - Response time
  - Token usage
  - Error rates

## Specific Code Changes Needed

### 1. Training Data Generation

**File**: `generate_generic_tool_usage_training.py`

**Changes**:
```python
# In system prompt, add:
"""
CRITICAL: When writing files, you must generate the COMPLETE file content.
Do NOT generate diffs, patches, or partial content.
The write_file tool expects the entire file content, not just changes.
"""

# In examples, ensure write_file always has complete content:
assistant_content_2 = f"""Now I'll generate the complete updated file content.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": modified_content  # COMPLETE file, not a diff
})}
</tool_call>"""
```

### 2. Inference Script

**File**: `inference_qwen3_with_tools.py`

**Changes**:
```python
# Add workflow validation
def validate_workflow(conversation_messages):
    """Ensure model follows correct workflow."""
    # Check: read_file before write_file
    # Check: write_file contains complete content (not diff-like)
    # Warn if natural language inference was used
    pass

# Reduce natural language inference
# Only use as last resort, log when used
# Prefer failing with clear error over silent inference
```

### 3. System Prompts

**Files**: All training data generation scripts

**Changes**:
- Add explicit workflow steps
- Emphasize "complete file content" not "diffs"
- Show examples of correct workflow

## Success Criteria

1. ✅ Model generates tool calls consistently
2. ✅ Model generates complete file content (not diffs)
3. ✅ Deterministic tools handle all filesystem operations
4. ✅ No content inference from training examples
5. ✅ Clear error messages when workflow is not followed
6. ✅ Reliable file operations without hallucinations

## Migration Path

1. **Immediate**: Update training data to emphasize full content generation
2. **Short-term**: Fix inference script to enforce workflow
3. **Medium-term**: Improve system prompts
4. **Long-term**: Consider hybrid deterministic/model approach

## Notes

- The deterministic tool approach (`inference_simple_file_ops.py`) is good for simple operations
- For complex operations (like adding Rego rules), we still need the model
- The key is ensuring the model follows the correct workflow: read → reason → generate full content → write
- Never let the model think it's doing diffs or patches
