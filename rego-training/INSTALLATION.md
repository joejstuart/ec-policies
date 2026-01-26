# Installation Guide

## Dependency Conflicts with Feast

If you encounter dependency conflicts with `feast` (or other packages), you have several options:

### Option 1: Use a Virtual Environment (Recommended)

This is the **best practice** and avoids all conflicts:

```bash
# Create virtual environment
python3 -m venv venv-training

# Activate it
source venv-training/bin/activate  # On Linux/macOS
# or
venv-training\Scripts\activate     # On Windows

# Install training requirements
pip install -r requirements-training.txt
```

### Option 2: Use Compatible Versions

If you must install in the same environment as `feast`, use the compatible requirements file:

```bash
pip install -r requirements-training-compatible.txt
```

**Note**: This uses older versions of `pyarrow` and `dill` that are compatible with `feast 0.54.1`. Some newer features may not be available, but basic training should work.

### Option 3: Update Feast (If Possible)

If you can update `feast`, newer versions may support newer dependencies:

```bash
pip install --upgrade feast
pip install -r requirements-training.txt
```

### Option 4: Ignore Conflicts (Not Recommended)

If you're certain `feast` won't be used during training, you can ignore the conflicts:

```bash
pip install -r requirements-training.txt --no-deps
pip install transformers datasets torch accelerate peft tensorboard
```

**Warning**: This may break `feast` functionality.

## Verifying Installation

After installation, verify all packages are available:

```bash
python3 -c "import transformers, datasets, torch, accelerate, peft, tensorboard; print('✅ All modules available')"
```

## Troubleshooting

### Import Errors

If you get import errors after installation:

1. **Check Python version**: Training requires Python 3.8+
   ```bash
   python3 --version
   ```

2. **Verify installation**:
   ```bash
   pip list | grep -E "transformers|datasets|torch|peft"
   ```

3. **Reinstall if needed**:
   ```bash
   pip install --force-reinstall -r requirements-training.txt
   ```

### CUDA/GPU Issues

If you have GPU issues:

1. **Check PyTorch CUDA support**:
   ```bash
   python3 -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"
   ```

2. **Install CUDA-enabled PyTorch** (if needed):
   ```bash
   pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
   ```

### Memory Issues

If you run out of memory during training:

1. Use LoRA (already in requirements): `--use-lora`
2. Reduce batch size: `--batch-size 4`
3. Use gradient accumulation: `--gradient-accumulation-steps 4`
4. Enable gradient checkpointing (already enabled by default)

## Recommended Setup

For production training, use a virtual environment:

```bash
# Create and activate venv
python3 -m venv ~/venv-rego-training
source ~/venv-rego-training/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
cd rego-training
pip install -r requirements-training.txt

# Verify
python3 -c "import transformers; print(f'Transformers version: {transformers.__version__}')"
```

This keeps your training dependencies isolated from other projects.
