#!/usr/bin/env python3
"""
Run inference with fine-tuned Qwen3 model for Rego policy generation.

This script loads a fine-tuned Qwen3 model and generates Rego code from
natural language policy requirements.

Usage:
    python inference_qwen3.py --model ./qwen3-rego-finetuned --prompt "Verify all tasks have status Succeeded"
    
    # Interactive mode
    python inference_qwen3.py --model ./qwen3-rego-finetuned --interactive
    
    # Generate tests for a rule
    python inference_qwen3.py --model ./qwen3-rego-finetuned --test-mode --rule-file annotation_049.rego
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Error: transformers library not found. Install with: pip install transformers torch")
    sys.exit(1)


def format_conversation(messages: list) -> str:
    """Format conversation messages into a single text string (same as training)."""
    formatted = ""
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        
        if role == "system":
            formatted += f"<|im_start|>system\n{content}<|im_end|>\n"
        elif role == "user":
            formatted += f"<|im_start|>user\n{content}<|im_end|>\n"
        elif role == "assistant":
            formatted += f"<|im_start|>assistant\n{content}<|im_end|>\n"
    
    return formatted


def get_system_prompt(mode: str = "rule") -> str:
    """Get appropriate system prompt based on mode."""
    if mode == "test":
        return """You are an expert at writing OPA Rego test files. You understand how to create comprehensive test cases for Rego policy rules following OPA testing best practices.

## OPA Testing Best Practices

1. **Test File Structure**:
   - Test files end with `_test.rego`
   - Test package uses `_test` suffix: `package {rule_package}_test`
   - Import the rule: `import data.{rule_package}`
   - Use `import rego.v1` for modern Rego syntax

2. **Test Rules**:
   - Test rules are prefixed with `test_`
   - Use `with input as {...}` to provide test data
   - For rules that should deny: `count({package}.deny) > 0`
   - For rules that should pass: `count({package}.deny) == 0`
   - All object keys in test data must be quoted strings

3. **Test Coverage**:
   - Create both positive (should deny) and negative (should pass) test cases
   - Use realistic attestation data from the Enterprise Contract structure
   - Test edge cases and boundary conditions

4. **Test Data**:
   - Use complete attestation structures with all required fields
   - Ensure test data matches the rule's validation requirements
   - Include both valid and invalid scenarios

Write comprehensive test files that provide full coverage of the Rego rule."""
    
    elif mode == "both":
        return """You are an expert at writing OPA Rego policy rules and their corresponding test files for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code with comprehensive tests.

## Attestation Structure

The input structure is:
- `input.attestations` - array of attestation objects
- Each attestation has `statement.predicate` containing build information
- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`
- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`
- Alternative path (some formats): `attestation.statement.predicate.buildDefinition.tasks`

## Task Structure
- `task.name` - task name
- `task.invocation.parameters` - object with parameter key-value pairs
- `task.invocation.parameters.<param_name>` - specific parameter value
- `task.ref.bundle` - OCI bundle reference
- `task.results` - array of task results
- `task.status` - task status (e.g., "Succeeded")

## Common Patterns
- Iterate attestations: `some attestation in input.attestations`
- Iterate tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
- Filter by name: `task.name == "<name>"`
- Check parameter: `task.invocation.parameters.<param> == "<value>"`

## OPA Testing Best Practices

1. **Test File Structure**:
   - Test files end with `_test.rego`
   - Test package uses `_test` suffix: `package {rule_package}_test`
   - Import the rule: `import data.{rule_package}`
   - Use `import rego.v1` for modern Rego syntax

2. **Test Rules**:
   - Test rules are prefixed with `test_`
   - Use `with input as {...}` to provide test data
   - For rules that should deny: `count({package}.deny) > 0`
   - For rules that should pass: `count({package}.deny) == 0`
   - All object keys in test data must be quoted strings

3. **Test Coverage**:
   - Create both positive (should deny) and negative (should pass) test cases
   - Use realistic attestation data
   - Test edge cases and boundary conditions

Write Rego deny rules that check the attestation structure, and create comprehensive test files for each rule."""
    
    else:  # rule mode
        return """You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.

## Attestation Structure

The input structure is:
- `input.attestations` - array of attestation objects
- Each attestation has `statement.predicate` containing build information
- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`
- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`
- Alternative path (some formats): `attestation.statement.predicate.buildDefinition.tasks`

## Task Structure
- `task.name` - task name
- `task.invocation.parameters` - object with parameter key-value pairs
- `task.invocation.parameters.<param_name>` - specific parameter value
- `task.ref.bundle` - OCI bundle reference
- `task.results` - array of task results
- `task.status` - task status (e.g., "Succeeded")

## Common Patterns
- Iterate attestations: `some attestation in input.attestations`
- Iterate tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
- Filter by name: `task.name == "<name>"`
- Check parameter: `task.invocation.parameters.<param> == "<value>"`

Write Rego deny rules that check the attestation structure."""


def generate(
    model,
    tokenizer,
    system_prompt: str,
    user_prompt: str,
    max_length: int = 2048,
    temperature: float = 0.7,
    top_p: float = 0.9,
    do_sample: bool = True,
) -> str:
    """Generate response from model."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    
    # Format conversation
    formatted = format_conversation(messages)
    
    # Tokenize
    inputs = tokenizer(
        formatted,
        return_tensors="pt",
        truncation=True,
        max_length=max_length,
    )
    
    # Move to device
    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in inputs.items()}
    
    # Generate
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=1024,
            temperature=temperature,
            top_p=top_p,
            do_sample=do_sample,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.convert_tokens_to_ids("<|im_end|>"),
        )
    
    # Decode
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=False)
    
    # Extract assistant response
    if "<|im_start|>assistant" in generated_text:
        assistant_part = generated_text.split("<|im_start|>assistant")[-1]
        if "<|im_end|>" in assistant_part:
            assistant_part = assistant_part.split("<|im_end|>")[0]
        return assistant_part.strip()
    else:
        # Fallback: return everything after the input
        if "<|im_end|>" in generated_text:
            parts = generated_text.split("<|im_end|>")
            if len(parts) > 2:
                return parts[-2].strip()
        return generated_text.split(formatted)[-1].strip() if formatted in generated_text else generated_text


def main():
    parser = argparse.ArgumentParser(
        description="Run inference with fine-tuned Qwen3 model for Rego generation"
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to fine-tuned model directory"
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Natural language policy requirement"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )
    parser.add_argument(
        "--test-mode",
        action="store_true",
        help="Generate tests for a rule (requires --rule-file)"
    )
    parser.add_argument(
        "--rule-file",
        type=str,
        default=None,
        help="Path to Rego rule file (for test generation)"
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="Generate both rule and tests from requirement"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=2048,
        help="Maximum input length (default: 2048)"
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Sampling temperature (default: 0.7)"
    )
    parser.add_argument(
        "--top-p",
        type=float,
        default=0.9,
        help="Top-p sampling (default: 0.9)"
    )
    parser.add_argument(
        "--device",
        type=str,
        default="auto",
        help="Device to use (auto, cpu, cuda) (default: auto)"
    )
    
    args = parser.parse_args()
    
    # Check model path
    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: Model path does not exist: {args.model}")
        sys.exit(1)
    
    # Determine device
    if args.device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        device = args.device
    
    print(f"Loading model from {args.model}...")
    print(f"Using device: {device}")
    
    # Load tokenizer
    try:
        tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
    except Exception as e:
        print(f"Error loading tokenizer: {e}")
        sys.exit(1)
    
    # Load model
    try:
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            trust_remote_code=True,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map="auto" if device == "cuda" else None,
        )
        if device == "cpu":
            model = model.to(device)
        model.eval()
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)
    
    print("Model loaded successfully!\n")
    
    # Interactive mode
    if args.interactive:
        print("Interactive mode - Enter prompts (type 'quit' to exit)")
        print("=" * 70)
        
        while True:
            try:
                prompt = input("\n> ")
                if prompt.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not prompt.strip():
                    continue
                
                system_prompt = get_system_prompt("rule")
                response = generate(
                    model, tokenizer, system_prompt, prompt,
                    max_length=args.max_length,
                    temperature=args.temperature,
                    top_p=args.top_p,
                )
                print("\n" + response + "\n")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
        
        return
    
    # Single prompt mode
    if args.test_mode:
        if not args.rule_file:
            print("Error: --test-mode requires --rule-file")
            sys.exit(1)
        
        # Read rule file
        rule_path = Path(args.rule_file)
        if not rule_path.exists():
            print(f"Error: Rule file not found: {args.rule_file}")
            sys.exit(1)
        
        with open(rule_path) as f:
            rule_content = f.read()
        
        # Extract package name
        import re
        package_match = re.search(r'^package\s+(\w+)', rule_content, re.MULTILINE)
        package_name = package_match.group(1) if package_match else "unknown"
        
        # Extract deny rule
        deny_match = re.search(r'deny.*?\{.*?\}', rule_content, re.DOTALL)
        deny_rule = deny_match.group(0) if deny_match else rule_content
        
        # Extract requirement from metadata if available
        title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', rule_content, re.MULTILINE)
        requirement = title_match.group(1).strip() if title_match else "Unknown requirement"
        
        user_prompt = f"""Given the following Rego policy rule, create a complete test file for it.

**Requirement**: {requirement}

**Rego Rule**:
```rego
package {package_name}

{deny_rule}
```

Create a `{package_name}_test.rego` file with comprehensive test cases."""
        
        system_prompt = get_system_prompt("test")
        
    elif args.both:
        if not args.prompt:
            print("Error: --both requires --prompt")
            sys.exit(1)
        
        user_prompt = f"""I need a Rego policy rule to validate the following requirement, along with a complete test file for it.

**Requirement**: {args.prompt}

Create:
1. A Rego rule file that implements the validation
2. A corresponding test file with comprehensive test cases"""
        
        system_prompt = get_system_prompt("both")
        
    else:
        if not args.prompt:
            print("Error: --prompt required (or use --interactive)")
            sys.exit(1)
        
        user_prompt = args.prompt
        system_prompt = get_system_prompt("rule")
    
    # Generate
    print("Generating response...")
    print("=" * 70)
    response = generate(
        model, tokenizer, system_prompt, user_prompt,
        max_length=args.max_length,
        temperature=args.temperature,
        top_p=args.top_p,
    )
    
    print(response)
    print("=" * 70)


if __name__ == "__main__":
    main()
