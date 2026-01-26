# Inference Examples

Here are 3 examples you can use to test your fine-tuned model:

## Example 1: Generate a Rego Rule

Generate a Rego rule from a natural language requirement:

```bash
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --prompt "Verify all tasks in the PipelineRun attestation have the annotation 'pipelinesascode.tekton.dev/state' set."
```

**Expected Output**: A Rego deny rule that checks for the annotation in all tasks.

---

## Example 2: Generate Tests for an Existing Rule

Generate comprehensive tests for an existing Rego rule:

```bash
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --test-mode \
  --rule-file rego_rules/annotation_049.rego
```

**Expected Output**: A complete `annotation_049_test.rego` file with positive and negative test cases.

---

## Example 3: Generate Both Rule and Tests

Generate both the Rego rule and its tests from a single requirement:

```bash
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --both \
  --prompt "Verify all materials with oci:// URI have SHA256 digest."
```

**Expected Output**: Both a Rego rule file and a corresponding test file.

---

## Additional Examples

### Interactive Mode

Start an interactive session to test multiple prompts:

```bash
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --interactive
```

Then you can enter prompts like:
- `Verify the build task has the annotation 'tekton.dev/tags' set to 'konflux'.`
- `Verify all tasks have status 'Succeeded'.`
- `Verify all subject images have a digest.`

### More Rule Generation Examples

```bash
# Check task status
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --prompt "Verify all tasks have status 'Succeeded'."

# Check subject images
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --prompt "Verify the attestation has at least one subject image."

# Check metadata timestamps
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --prompt "Verify buildFinishedOn is after buildStartedOn."
```

### Test Generation for Different Rules

```bash
# Generate tests for a top-level rule
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --test-mode \
  --rule-file rego_rules/top_level_001.rego

# Generate tests for a compound rule
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --test-mode \
  --rule-file rego_rules/compound_001.rego

# Generate tests for a step rule
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --test-mode \
  --rule-file rego_rules/step_027.rego
```

---

## Tips

1. **Temperature**: Lower temperature (0.3-0.5) for more deterministic output, higher (0.7-1.0) for more creative responses
2. **GPU**: The script automatically uses GPU if available
3. **Model Path**: Make sure the model path points to your fine-tuned model directory (should contain `config.json`, `pytorch_model.bin`, etc.)

## Troubleshooting

If you get errors:
- Make sure the model directory exists and contains the fine-tuned model files
- Check that transformers and torch are installed: `pip install transformers torch`
- For GPU issues, check CUDA availability: `python -c "import torch; print(torch.cuda.is_available())"`
