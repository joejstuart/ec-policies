# File Editing Example Prompts

This guide provides example prompts you can use with `inference_qwen3_with_tools.py` for editing Rego policy files.

## Basic File Editing

### Add a New Rule to an Existing File

```
Add a new rule to policy/release/example.rego that verifies all tasks have status "Succeeded"
```

```
Read the file at policy/release/annotation_049.rego and add a new rule that checks if any task has a missing name field
```

```
Edit policy/release/example.rego to add a rule that validates task parameters are not empty
```

### Edit a Specific Rule

```
Read policy/release/example.rego and modify the existing deny rule to also check that task.status is not "Failed"
```

```
Update the rule in policy/release/example.rego to exclude skipped tasks from validation
```

### Add Multiple Rules

```
Add two new rules to policy/release/example.rego:
1. Verify all tasks have a valid bundle reference
2. Check that no tasks use untrusted images
```

## File Creation

### Create a New Policy File

```
Create a new file at policy/release/task_validation.rego with a rule that verifies all tasks succeeded
```

```
Write a new Rego policy file at policy/release/build_checks.rego that contains:
- A rule checking task status
- A rule validating task parameters
- Proper package declaration and imports
```

## Complex Editing Scenarios

### Add Rule with Metadata

```
Add a new rule to policy/release/example.rego with:
- Title: "Verify task completion"
- Description: "Ensures all tasks have completed successfully"
- The rule should check task.status == "Succeeded"
```

### Modify Existing Rule Structure

```
Read policy/release/example.rego and update the deny rule to:
1. Add a condition to exclude skipped tasks
2. Include the task name in the error message
3. Maintain all existing helper rules
```

### Add Helper Functions

```
Add a helper function to policy/release/example.rego that extracts task names, then use it in the deny rule
```

## Interactive Workflow Examples

### Step-by-Step Editing

**First prompt:**
```
Read the file at policy/release/example.rego
```

**After seeing the file contents, follow up:**
```
Now add a new rule after the existing deny rules that checks task.invocation.parameters are not empty
```

**Then:**
```
Save the updated file
```

### Multi-File Operations

```
Read policy/release/example.rego and policy/release/another.rego, then add similar validation rules to both files
```

## Domain-Specific Examples

### Task Status Validation

```
Add a rule to policy/release/example.rego that denies if any task in the build attestation has a status other than "Succeeded" or "Skipped"
```

### Parameter Validation

```
Create a rule in policy/release/example.rego that verifies all tasks have required parameters set, excluding tasks that are skipped
```

### Bundle Reference Checks

```
Add validation to policy/release/example.rego to ensure all task references include a valid bundle URI
```

### Image Validation

```
Edit policy/release/example.rego to add a rule checking that no tasks use images from untrusted registries
```

## Format-Specific Instructions

### Preserve Existing Structure

```
Read policy/release/example.rego and add a new deny rule while preserving:
- The existing package declaration
- All current imports
- The order of existing rules
- All helper functions
```

### Follow Conventions

```
Add a new rule to policy/release/example.rego following the existing code style:
- Use rego.v1 import
- Include METADATA annotations
- Place deny rules before helper rules
- Use proper indentation
```

## Error Recovery

### Fix Syntax Errors

```
Read policy/release/example.rego and fix any syntax errors in the deny rules
```

### Update Deprecated Patterns

```
Update policy/release/example.rego to use modern Rego syntax (rego.v1) instead of legacy syntax
```

## Complete Examples

### Full Workflow

```
I need to add a new validation rule. Here's what to do:
1. Read policy/release/example.rego
2. Add a new rule that checks task.status == "Succeeded"
3. Include proper METADATA annotations
4. Save the file
```

### Complex Rule Addition

```
Add a comprehensive validation rule to policy/release/example.rego that:
- Checks all tasks have status "Succeeded"
- Excludes tasks that are explicitly marked as skipped
- Includes the task name in error messages
- Uses helper functions for readability
- Follows the existing file structure
```

## Tips for Best Results

1. **Be Specific**: Include the exact file path
   - ✅ Good: `policy/release/example.rego`
   - ❌ Bad: `the file` or `example.rego`

2. **Describe the Rule Clearly**: Explain what the rule should validate
   - ✅ Good: "Verify all tasks have status Succeeded"
   - ❌ Bad: "Add a rule"

3. **Specify Location**: Where in the file to add the rule
   - ✅ Good: "Add after the existing deny rules"
   - ❌ Bad: "Add somewhere"

4. **Mention Requirements**: Include any special requirements
   - ✅ Good: "Include METADATA annotations and preserve existing structure"
   - ❌ Bad: "Add a rule"

5. **Use Natural Language**: Describe what you want, not how to code it
   - ✅ Good: "Check that all tasks completed successfully"
   - ❌ Bad: "Write a deny rule with task.status check"

## Command Examples

### Basic Usage

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --prompt "Add a new rule to policy/release/example.rego that verifies all tasks have status Succeeded"
```

### With Verbose Output

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --prompt "Read policy/release/example.rego and add a validation rule" \
    --verbose
```

### Interactive Mode

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --interactive \
    --verbose
```

Then enter prompts interactively:
```
> Read policy/release/example.rego
> Add a new rule checking task status
> Save the file
```

## Expected Behavior

When you use these prompts, the model should:

1. **Read the file** using `read_file` tool
2. **Analyze the structure** (package, imports, existing rules)
3. **Generate the new rule** with proper formatting
4. **Write the updated file** using `write_file` tool
5. **Confirm completion**

The verbose output will show each step, making it easy to debug if something goes wrong.
