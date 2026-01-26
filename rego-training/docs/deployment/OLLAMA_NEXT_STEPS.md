# Next Steps: Deploy to Ollama

## Step 1: Locate Your GGUF File

Find where the conversion script saved your GGUF file:

```bash
# Check common locations
ls -lh llama.cpp/*.gguf
ls -lh qwen3-ollama*.gguf
find . -name "*.gguf" -type f
```

The file should be named something like:
- `qwen3-ollama.gguf`
- `qwen3-ollama-f16.gguf`
- Or whatever you specified with `--outfile`

## Step 2: Create the Modelfile

Use the helper script to generate the Modelfile:

```bash
python create_ollama_modelfile.py \
  --gguf-model <path-to-your-gguf-file> \
  --output Modelfile \
  --model-name qwen3-rego
```

**Example** (if GGUF is in llama.cpp directory):
```bash
python create_ollama_modelfile.py \
  --gguf-model llama.cpp/qwen3-ollama.gguf \
  --output Modelfile \
  --model-name qwen3-rego
```

Or create it manually - the script will show you the exact path to use.

## Step 3: Import Model to Ollama

```bash
ollama create qwen3-rego -f Modelfile
```

This will:
- Load the GGUF model
- Apply the Modelfile settings
- Make it available as `qwen3-rego`

## Step 4: Verify Installation

```bash
# List installed models
ollama list

# You should see qwen3-rego in the list
```

## Step 5: Test the Model

### Basic Test

```bash
ollama run qwen3-rego "Verify all tasks have status 'Succeeded'."
```

### Interactive Mode

```bash
ollama run qwen3-rego
```

Then enter prompts like:
- `Verify all tasks have status 'Succeeded'.`
- `Verify the build task has the annotation 'tekton.dev/tags' set to 'konflux'.`
- `Verify all materials with oci:// URI have SHA256 digest.`

### Using Python API

```python
import ollama

response = ollama.chat(
    model='qwen3-rego',
    messages=[
        {
            'role': 'user',
            'content': 'Verify all tasks have status Succeeded.'
        }
    ]
)

print(response['message']['content'])
```

### Using REST API

```bash
curl http://localhost:11434/api/generate -d '{
  "model": "qwen3-rego",
  "prompt": "Verify all tasks have status Succeeded.",
  "stream": false
}'
```

## Step 6: Test Different Modes

### Rule Generation
```bash
ollama run qwen3-rego "Verify all tasks have the annotation 'pipelinesascode.tekton.dev/state' set."
```

### Test Generation (requires providing rule in prompt)
```bash
ollama run qwen3-rego "Given this Rego rule:
\`\`\`rego
package annotation_049
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    not task.invocation.environment.annotations[\"pipelinesascode.tekton.dev/state\"]
    result := \"Task does not have annotation\"
}
\`\`\`
Create tests for it."
```

## Troubleshooting

### Model Not Found
If `ollama list` doesn't show your model:
- Check the Modelfile path is correct
- Verify the GGUF file exists and is readable
- Check for errors during `ollama create`

### Wrong Output Format
If the model doesn't generate Rego code correctly:
- Verify the Modelfile template matches Qwen3 format
- Check that system prompt is appropriate
- Try adjusting temperature: `ollama run qwen3-rego --temperature 0.7`

### Memory Issues
If Ollama runs out of memory:
- Use a quantized model (Q4_K_M or Q5_K_M)
- Reduce context window in Modelfile: `PARAMETER num_ctx 2048`

## Quick Reference

```bash
# Create model
ollama create qwen3-rego -f Modelfile

# Run inference
ollama run qwen3-rego "Your prompt here"

# List models
ollama list

# Remove model (if needed)
ollama rm qwen3-rego

# Show model info
ollama show qwen3-rego
```

## Next: Integration

Once working, you can:
1. **Integrate into your workflow** - Use Ollama API in your scripts
2. **Create wrapper scripts** - Make it easier to generate rules/tests
3. **Set up as a service** - Run Ollama as a background service
4. **Share with team** - Others can pull the model: `ollama pull qwen3-rego`
