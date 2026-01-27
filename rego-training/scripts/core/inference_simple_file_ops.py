#!/usr/bin/env python3
"""
Simple file operations inference - deterministic file I/O with model for content generation.

This approach separates concerns:
- File operations: Deterministic (read, write, create)
- Content generation: Use model (for rules, code, etc.)

This is more reliable than trying to get the model to generate tool calls.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Tuple

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Error: transformers library not found. Install with: pip install transformers torch")
    sys.exit(1)

from inference_qwen3 import generate, get_system_prompt


def read_file_tool(file_path: str) -> str:
    """Read a file."""
    try:
        path = Path(file_path)
        if not path.exists():
            return f"Error: File not found: {file_path}"
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


def write_file_tool(file_path: str, contents: str) -> str:
    """Write to a file."""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(contents)
        return "File written successfully."
    except Exception as e:
        return f"Error writing file: {str(e)}"


def parse_user_intent(user_prompt: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Parse user intent to determine file operation.
    
    Returns:
        (operation, file_path, content)
        operation: 'create', 'read', 'edit', 'add', 'delete', 'unknown'
    """
    prompt_lower = user_prompt.lower()
    
    # Extract file path
    file_path = None
    path_match = re.search(r'(?:file|named|at|to|in)\s+(?:`)?([^\s`]+\.\w+)(?:`)?', user_prompt, re.IGNORECASE)
    if not path_match:
        path_match = re.search(r'(\w+\.\w+)', user_prompt)
    if path_match:
        file_path = path_match.group(1)
    
    # Determine operation
    if "create" in prompt_lower or "new file" in prompt_lower:
        # Extract content if specified
        content = None
        content_match = re.search(r"(?:with|containing|content)\s+['\"]([^'\"]+)['\"]", user_prompt, re.IGNORECASE)
        if content_match:
            content = content_match.group(1)
        return ("create", file_path, content)
    
    elif "read" in prompt_lower or "show" in prompt_lower or "display" in prompt_lower:
        return ("read", file_path, None)
    
    elif "add" in prompt_lower and ("content" in prompt_lower or "text" in prompt_lower or "line" in prompt_lower):
        # Extract content to add
        content = None
        content_match = re.search(r"(?:content|text|line)\s+['\"]([^'\"]+)['\"]", user_prompt, re.IGNORECASE)
        if not content_match:
            content_match = re.search(r"['\"]([^'\"]+)['\"]", user_prompt)
        if content_match:
            content = content_match.group(1)
        return ("add", file_path, content)
    
    elif "edit" in prompt_lower or "modify" in prompt_lower or "update" in prompt_lower:
        return ("edit", file_path, None)
    
    elif "delete" in prompt_lower or "remove" in prompt_lower:
        return ("delete", file_path, None)
    
    else:
        return ("unknown", file_path, None)


def execute_file_operation(
    operation: str,
    file_path: Optional[str],
    content: Optional[str],
    model=None,
    tokenizer=None,
    system_prompt: str = ""
) -> Tuple[str, bool]:
    """
    Execute a file operation deterministically.
    
    Returns:
        (result_message, success)
    """
    if not file_path:
        return "Error: No file path specified", False
    
    if operation == "create":
        # Create file with specified content or empty
        file_contents = content if content else ""
        result = write_file_tool(file_path, file_contents)
        if "Error" in result:
            return result, False
        return f"Created file {file_path}" + (f" with content" if content else " (empty)"), True
    
    elif operation == "read":
        result = read_file_tool(file_path)
        if "Error" in result:
            return result, False
        return f"File contents:\n\n{result}", True
    
    elif operation == "add":
        if not content:
            return "Error: No content specified to add", False
        
        # Read existing file
        existing = read_file_tool(file_path)
        if "Error" in existing:
            return existing, False
        
        # Append content
        new_content = existing + "\n" + content if existing else content
        result = write_file_tool(file_path, new_content)
        if "Error" in result:
            return result, False
        return f"Added '{content}' to {file_path}", True
    
    elif operation == "edit":
        # For editing, we might need the model to generate the edit
        # For now, just read the file
        result = read_file_tool(file_path)
        if "Error" in result:
            return result, False
        return f"File contents (ready for editing):\n\n{result}", True
    
    elif operation == "delete":
        try:
            path = Path(file_path)
            if path.exists():
                path.unlink()
                return f"Deleted file {file_path}", True
            else:
                return f"Error: File not found: {file_path}", False
        except Exception as e:
            return f"Error deleting file: {str(e)}", False
    
    else:
        return f"Unknown operation: {operation}", False


def main():
    parser = argparse.ArgumentParser(
        description="Simple file operations with deterministic I/O"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to model (optional, for content generation)"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Single prompt"
    )
    
    args = parser.parse_args()
    
    # Load model if provided (for content generation)
    model = None
    tokenizer = None
    if args.model:
        model_path = Path(args.model)
        if not model_path.exists():
            print(f"Error: Model path does not exist: {args.model}")
            sys.exit(1)
        
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Loading model from {args.model}...")
        print(f"Using device: {device}")
        
        try:
            tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            model = AutoModelForCausalLM.from_pretrained(
                args.model,
                trust_remote_code=True,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map="auto" if device == "cuda" else None,
            )
            if device == "cpu":
                model = model.to(device)
            model.eval()
            print("Model loaded successfully!\n")
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)
    
    # Interactive mode
    if args.interactive:
        print("Simple File Operations - Enter commands (type 'quit' to exit)")
        print("=" * 70)
        print("\nExamples:")
        print("  create a file named test.txt")
        print("  create a file named test.txt with content 'Hello'")
        print("  read the file test.txt")
        print("  add the content 'World' to the file test.txt")
        print("=" * 70)
        
        while True:
            try:
                prompt = input("\n> ")
                if prompt.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not prompt.strip():
                    continue
                
                # Parse intent
                operation, file_path, content = parse_user_intent(prompt)
                
                print(f"\nOperation: {operation}")
                if file_path:
                    print(f"File: {file_path}")
                if content:
                    print(f"Content: {content}")
                
                # Execute operation
                result, success = execute_file_operation(
                    operation, file_path, content, model, tokenizer
                )
                
                print(f"\n{result}")
                if success:
                    print("✅ Operation completed")
                else:
                    print("❌ Operation failed")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
                import traceback
                traceback.print_exc()
        
        return
    
    # Single prompt mode
    if not args.prompt:
        print("Error: --prompt required (or use --interactive)")
        sys.exit(1)
    
    operation, file_path, content = parse_user_intent(args.prompt)
    result, success = execute_file_operation(operation, file_path, content, model, tokenizer)
    
    print(result)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
