# GGUF Conversion Troubleshooting

## Issue: AttributeError with extra_special_tokens

### Problem
When converting Qwen3 models to GGUF, you may encounter:
```
AttributeError: 'list' object has no attribute 'keys'
```

This happens because Qwen3 tokenizers have `extra_special_tokens` as a list, but the conversion script expects it to be a dict or absent.

### Solution

**Step 1: Fix the tokenizer config**

```bash
python fix_tokenizer_for_gguf.py --model-path ./qwen3-rego-finetuned-merged
```

This script:
- Removes the problematic `extra_special_tokens` list
- Ensures other special token fields are properly formatted
- Creates a backup of the original config

**Step 2: Try conversion again**

```bash
cd llama.cpp
python convert_hf_to_gguf.py \
  ../qwen3-rego-finetuned-merged \
  --outfile qwen3-ollama \
  --outtype f16
```

### Alternative: Manual Fix

If the script doesn't work, manually edit `tokenizer_config.json`:

```bash
# Backup first
cp qwen3-rego-finetuned-merged/tokenizer_config.json \
   qwen3-rego-finetuned-merged/tokenizer_config.json.backup

# Remove extra_special_tokens field
python3 << EOF
import json
with open('qwen3-rego-finetuned-merged/tokenizer_config.json') as f:
    config = json.load(f)
if 'extra_special_tokens' in config:
    del config['extra_special_tokens']
with open('qwen3-rego-finetuned-merged/tokenizer_config.json', 'w') as f:
    json.dump(config, f, indent=2)
print("✅ Removed extra_special_tokens")
EOF
```

### Alternative Conversion Methods

If llama.cpp conversion still fails, try:

#### Option 1: Use `llama-cpp-python` converter

```bash
pip install llama-cpp-python[convert]
python -m llama_cpp.convert_hf_to_gguf \
  --model-dir ./qwen3-rego-finetuned-merged \
  --outfile qwen3-ollama.gguf \
  --outtype f16
```

#### Option 2: Use `transformers` to export, then convert

```python
from transformers import AutoModelForCausalLM
import torch

model = AutoModelForCausalLM.from_pretrained(
    "./qwen3-rego-finetuned-merged",
    torch_dtype=torch.float16
)

# Save in a format that's easier to convert
# (This is a workaround if direct conversion fails)
```

#### Option 3: Check llama.cpp version

Make sure you have a recent version of llama.cpp that supports Qwen3:

```bash
cd llama.cpp
git pull
# Check if Qwen3 is in the supported models list
```

### Verification

After fixing, verify the tokenizer loads:

```python
from transformers import AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained(
    "./qwen3-rego-finetuned-merged",
    trust_remote_code=True
)
print("✅ Tokenizer loads successfully")
```

### Common Issues

1. **"No module named 'gguf'"**
   - Make sure you're running from the llama.cpp directory
   - Or install: `pip install gguf`

2. **"Model not supported"**
   - Check if Qwen3 is supported in your llama.cpp version
   - May need to update llama.cpp

3. **"Out of memory"**
   - Use quantization: `--outtype q4_k_m` instead of `f16`
   - This reduces model size significantly

### Quantization Options

If memory is an issue, use quantization:

```bash
# Q4_K_M (recommended balance)
python convert_hf_to_gguf.py \
  ../qwen3-rego-finetuned-merged \
  --outfile qwen3-ollama-q4 \
  --outtype q4_k_m

# Q5_K_M (better quality, larger)
python convert_hf_to_gguf.py \
  ../qwen3-rego-finetuned-merged \
  --outfile qwen3-ollama-q5 \
  --outtype q5_k_m
```

Quantization reduces model size:
- F16: ~3.4GB
- Q4_K_M: ~1.7GB
- Q5_K_M: ~2.1GB

### Next Steps After Conversion

Once you have the GGUF file:

1. Create Modelfile:
```bash
python create_ollama_modelfile.py \
  --gguf-model ./qwen3-ollama.gguf \
  --output Modelfile
```

2. Import to Ollama:
```bash
ollama create qwen3-rego -f Modelfile
```

3. Test:
```bash
ollama run qwen3-rego "Verify all tasks have status Succeeded."
```
