#!/usr/bin/env python3
"""
Run inference with fine-tuned Qwen3 model supporting tool calls (read_file, write_file).

This script loads a fine-tuned Qwen3 model and can execute tool calls for file operations.

Usage:
    # Edit a file
    python inference_qwen3_with_tools.py \
        --model ./qwen3-rego-finetuned \
        --prompt "Add a new rule to policy/release/example.rego: Verify all tasks succeed"
    
    # Interactive mode with tools
    python inference_qwen3_with_tools.py \
        --model ./qwen3-rego-finetuned \
        --interactive
"""

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Error: transformers library not found. Install with: pip install transformers torch")
    sys.exit(1)


def read_file_tool(file_path: str) -> str:
    """Execute read_file tool."""
    try:
        path = Path(file_path)
        if not path.exists():
            return f"Error: File not found: {file_path}"
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


def write_file_tool(file_path: str, contents: str) -> str:
    """Execute write_file tool."""
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(contents)
        return "File written successfully."
    except Exception as e:
        return f"Error writing file: {str(e)}"


def parse_tool_calls(text: str) -> List[Dict]:
    """
    Parse tool calls from model output.
    
    The model may output tool calls in various formats. We try to extract:
    1. XML-style tool calls: <tool_call>name: TOOL_NAME\narguments: {...}</tool_call> (NEW FORMAT)
    2. JSON tool_calls array (if model outputs structured format)
    3. Function call patterns in text
    4. JSON function objects
    """
    tool_calls = []
    
    # First, try to parse XML-style tool calls (new improved format)
    # Pattern: <tool_call>\nname: TOOL_NAME\narguments: {...}\n</tool_call>
    xml_pattern = r'<tool_call>\s*name:\s*(\w+)\s*arguments:\s*(\{.*?\})\s*</tool_call>'
    for match in re.finditer(xml_pattern, text, re.DOTALL):
        tool_name = match.group(1).strip()
        args_str = match.group(2).strip()
        
        try:
            # Parse the arguments JSON
            arguments = json.loads(args_str)
            
            # Create tool call structure
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json.dumps(arguments)
                }
            })
        except json.JSONDecodeError:
            # Try to fix common JSON issues (trailing commas, unquoted keys)
            try:
                # Remove trailing commas
                args_str_fixed = re.sub(r',\s*}', '}', args_str)
                args_str_fixed = re.sub(r',\s*]', ']', args_str_fixed)
                # Try to quote unquoted keys (simple case)
                args_str_fixed = re.sub(r'(\w+):', r'"\1":', args_str_fixed)
                arguments = json.loads(args_str_fixed)
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:12]}",
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments)
                    }
                })
            except:
                # If still can't parse, skip this tool call
                pass
    
    # If we found XML-style tool calls, return them (they're the new format)
    if tool_calls:
        return tool_calls
    
    # Try to find JSON tool_calls array (full structure)
    # Pattern: {"tool_calls": [{"id": "...", "type": "function", "function": {...}}]}
    # Or just: [{"id": "...", "type": "function", "function": {...}}]
    
    # First, try to find a complete JSON object with tool_calls
    tool_calls_pattern = r'"tool_calls"\s*:\s*\[(.*?)\]'
    tool_calls_match = re.search(tool_calls_pattern, text, re.DOTALL)
    if tool_calls_match:
        try:
            # Try to parse as JSON array
            array_str = "[" + tool_calls_match.group(1) + "]"
            calls = json.loads(array_str)
            for call in calls:
                if isinstance(call, dict) and "function" in call:
                    tool_calls.append(call)
        except:
            pass
    
    # Also try to find a standalone JSON array of tool calls
    if not tool_calls:
        # Look for array starting with tool call structure
        array_pattern = r'\[\s*\{\s*"id"\s*:\s*"[^"]+"\s*,\s*"type"\s*:\s*"function"\s*,\s*"function"\s*:\s*\{[^}]+\}\s*\}'
        array_match = re.search(array_pattern, text, re.DOTALL)
        if array_match:
            try:
                # Find the complete array
                start = text.find('[', array_match.start())
                if start != -1:
                    # Try to find matching closing bracket
                    depth = 0
                    end = start
                    for i in range(start, len(text)):
                        if text[i] == '[':
                            depth += 1
                        elif text[i] == ']':
                            depth -= 1
                            if depth == 0:
                                end = i + 1
                                break
                    if end > start:
                        array_str = text[start:end]
                        calls = json.loads(array_str)
                        for call in calls:
                            if isinstance(call, dict) and "function" in call:
                                tool_calls.append(call)
            except:
                pass
    
    # Try to find individual function call objects
    # Pattern: {"id": "...", "type": "function", "function": {"name": "...", "arguments": "..."}}
    # Use a more flexible pattern that handles nested JSON
    function_call_pattern = r'\{\s*"id"\s*:\s*"[^"]+"\s*,\s*"type"\s*:\s*"function"\s*,\s*"function"\s*:\s*\{[^}]+\}\s*\}'
    for match in re.finditer(function_call_pattern, text, re.DOTALL):
        try:
            call = json.loads(match.group(0))
            if "function" in call:
                tool_calls.append(call)
        except:
            pass
    
    # Try to find function call objects with more flexible matching (handles nested braces)
    if not tool_calls:
        # Look for {"id": "...", "type": "function", "function": {...}}
        # This is tricky because of nested JSON, so we'll try a simpler approach
        # Look for the pattern and try to extract it
        id_pattern = r'"id"\s*:\s*"([^"]+)"'
        name_pattern = r'"name"\s*:\s*"([^"]+)"'
        args_pattern = r'"arguments"\s*:\s*"([^"]+)"'
        
        # Find all potential tool call starts
        for id_match in re.finditer(id_pattern, text):
            # Look for "type": "function" nearby
            start = max(0, id_match.start() - 50)
            end = min(len(text), id_match.end() + 500)
            snippet = text[start:end]
            
            if re.search(r'"type"\s*:\s*"function"', snippet):
                # Try to find name and arguments
                name_match = re.search(name_pattern, snippet)
                args_match = re.search(args_pattern, snippet)
                
                if name_match and args_match:
                    # Try to construct a tool call
                    func_name = name_match.group(1)
                    args_str = args_match.group(1)
                    
                    # Check if we already have this
                    if not any(
                        call.get("function", {}).get("name") == func_name and
                        call.get("function", {}).get("arguments") == args_str
                        for call in tool_calls
                    ):
                        try:
                            # Validate args is valid JSON
                            json.loads(args_str)
                            tool_calls.append({
                                "id": id_match.group(1),
                                "type": "function",
                                "function": {
                                    "name": func_name,
                                    "arguments": args_str
                                }
                            })
                        except:
                            pass
    
    # Try to find simplified function calls: {"name": "read_file", "arguments": {...}}
    simple_function_pattern = r'\{\s*"name"\s*:\s*"(\w+)"\s*,\s*"arguments"\s*:\s*(\{.*?\})\s*\}'
    for match in re.finditer(simple_function_pattern, text, re.DOTALL):
        func_name = match.group(1)
        try:
            args = json.loads(match.group(2))
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": func_name,
                    "arguments": json.dumps(args)
                }
            })
        except:
            pass
    
    # Try to find function call patterns: read_file("path") or write_file("path", "contents")
    # This is a fallback for when model outputs natural language with function calls
    read_pattern = r'read_file\s*\(\s*["\']([^"\']+)["\']\s*\)'
    for match in re.finditer(read_pattern, text):
        # Check if we already have this as a structured call
        path = match.group(1)
        if not any(
            call.get("function", {}).get("name") == "read_file" and
            json.loads(call.get("function", {}).get("arguments", "{}")).get("path") == path
            for call in tool_calls
        ):
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": json.dumps({"path": path})
                }
            })
    
    # For write_file, we need to handle multi-line contents
    # Look for write_file("path", ...) patterns
    write_pattern = r'write_file\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']'
    for match in re.finditer(write_pattern, text):
        path = match.group(1)
        # Try to find the full contents (might be multi-line)
        # This is a simplified version - full parsing would need more context
        if not any(
            call.get("function", {}).get("name") == "write_file" and
            json.loads(call.get("function", {}).get("arguments", "{}")).get("path") == path
            for call in tool_calls
        ):
            # For now, we'll skip simple pattern matching for write_file
            # as it's complex to extract full contents from text
            pass
    
    return tool_calls


def format_messages_for_generation(messages: List[Dict]) -> str:
    """Format messages for model generation (Qwen chat format)."""
    formatted = ""
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        
        if role == "system":
            formatted += f"<|im_start|>system\n{content}<|im_end|>\n"
        elif role == "user":
            formatted += f"<|im_start|>user\n{content}<|im_end|>\n"
        elif role == "assistant":
            formatted += f"<|im_start|>assistant\n{content}"
            # Add tool calls if present (for conversation history)
            # Note: In training, tool_calls are a separate key, not in the text
            # So we don't add them to the formatted text - the model should generate them
            # formatted += f"\n\nTool calls:\n{tool_calls_json}"
            formatted += "<|im_end|>\n"
        elif role == "tool":
            # Tool responses - format as tool role for context
            formatted += f"<|im_start|>tool\n{content}<|im_end|>\n"
    
    # Ensure we end with user or assistant (not tool) so model knows to generate
    # Add assistant start token if last message was tool (model should continue)
    if messages and messages[-1].get("role") == "tool":
        formatted += "<|im_start|>assistant\n"
    
    return formatted


def execute_tool_call(tool_call: Dict) -> Tuple[str, str]:
    """Execute a tool call and return the result."""
    func = tool_call.get("function", {})
    func_name = func.get("name", "")
    args_str = func.get("arguments", "{}")
    
    try:
        args = json.loads(args_str)
    except:
        return "", f"Error: Invalid arguments JSON: {args_str}"
    
    if func_name == "read_file":
        path = args.get("path", "")
        if not path:
            return "", "Error: read_file requires 'path' argument"
        result = read_file_tool(path)
        return result, ""
    
    elif func_name == "write_file":
        path = args.get("path", "")
        contents = args.get("contents", "")
        if not path:
            return "", "Error: write_file requires 'path' argument"
        result = write_file_tool(path, contents)
        return result, ""
    
    else:
        return "", f"Error: Unknown tool: {func_name}"


def generate_with_tools(
    model,
    tokenizer,
    messages: List[Dict],
    max_length: int = 3072,
    temperature: float = 0.7,
    top_p: float = 0.9,
    max_iterations: int = 10,
    verbose: bool = False,
) -> Tuple[List[Dict], str]:
    """
    Generate response with tool support.
    
    Returns:
        - Updated messages list (with tool calls and responses)
        - Final assistant response text
    """
    conversation_messages = messages.copy()
    iteration = 0
    
    while iteration < max_iterations:
        iteration += 1
        
        # Format for generation
        formatted = format_messages_for_generation(conversation_messages)
        
        # Ensure we're prompting for assistant response
        # If the last message wasn't assistant, add assistant start token
        if conversation_messages and conversation_messages[-1].get("role") != "assistant":
            if not formatted.endswith("<|im_start|>assistant\n"):
                formatted += "<|im_start|>assistant\n"
        
        if verbose and iteration == 1:
            print(f"\n[Iteration {iteration}] Formatted prompt (last 200 chars):")
            print(formatted[-200:])
        
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
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.convert_tokens_to_ids("<|im_end|>"),
            )
        
        # Decode - only get the newly generated tokens (not the input)
        input_length = inputs['input_ids'].shape[1]
        generated_tokens = outputs[0][input_length:]
        generated_text = tokenizer.decode(generated_tokens, skip_special_tokens=False)
        
        if verbose:
            print(f"\n[Iteration {iteration}] Raw generated text (first 500 chars):")
            print(generated_text[:500])
            print(f"\n[Iteration {iteration}] Full generated text length: {len(generated_text)} chars")
        
        # Extract assistant response
        # The model should generate: <|im_start|>assistant\n{content}<|im_end|>
        # Or just the content if it doesn't include the tags
        assistant_content = ""
        
        if "<|im_start|>assistant" in generated_text:
            assistant_part = generated_text.split("<|im_start|>assistant")[-1]
            if "<|im_end|>" in assistant_part:
                assistant_part = assistant_part.split("<|im_end|>")[0]
            # Remove leading newline if present
            assistant_content = assistant_part.lstrip('\n').strip()
        elif "<|im_end|>" in generated_text:
            # Just extract content before the end token
            assistant_content = generated_text.split("<|im_end|>")[0].strip()
        else:
            # Use the generated text as-is (might not have special tokens)
            assistant_content = generated_text.strip()
        
        # Filter out common echo patterns
        # If the content starts with user prompt markers, it's likely an echo
        if assistant_content.startswith("<|im_start|>user"):
            # Extract everything after the user tag
            parts = assistant_content.split("<|im_start|>user")
            if len(parts) > 1:
                # Try to find assistant content after user content
                remaining = parts[-1]
                if "<|im_start|>assistant" in remaining:
                    assistant_content = remaining.split("<|im_start|>assistant")[-1]
                    if "<|im_end|>" in assistant_content:
                        assistant_content = assistant_content.split("<|im_end|>")[0]
                    assistant_content = assistant_content.strip()
                else:
                    # No assistant tag found, this is likely just an echo
                    assistant_content = ""
        
        # If content looks like it's echoing the user prompt, it's probably wrong
        if assistant_content and (
            assistant_content.startswith("Create a Rego deny rule") or
            assistant_content.startswith("Verify all tasks") or
            "<|im_start|>user" in assistant_content
        ):
            # This is likely an echo - try to find actual response
            # Sometimes the model generates the full conversation, extract just assistant part
            if "<|im_start|>assistant" in generated_text:
                parts = generated_text.split("<|im_start|>assistant")
                if len(parts) > 1:
                    assistant_part = parts[-1]
                    if "<|im_end|>" in assistant_part:
                        assistant_part = assistant_part.split("<|im_end|>")[0]
                    assistant_content = assistant_part.strip()
                else:
                    assistant_content = ""
            else:
                # If no assistant tag and it looks like echo, use empty or raw
                # Sometimes models generate without tags
                if len(assistant_content) < 50 and ("Create" in assistant_content or "Verify" in assistant_content):
                    # Likely an echo, use the raw generated text but skip echo patterns
                    assistant_content = generated_text.strip()
                    # Remove any leading user prompt patterns
                    for pattern in ["<|im_start|>user", "Create a Rego deny rule", "Verify all tasks"]:
                        if assistant_content.startswith(pattern):
                            # Try to find content after this
                            remaining = assistant_content[len(pattern):].strip()
                            if remaining:
                                assistant_content = remaining
                            else:
                                assistant_content = ""
                                break
        
        # Parse tool calls from the content (before cleaning)
        tool_calls = parse_tool_calls(assistant_content)
        
        # Also check the raw generated text for tool calls (might be in different format)
        if not tool_calls:
            tool_calls = parse_tool_calls(generated_text)
        
        # Remove tool call JSON from the displayed content (clean it up)
        # The model might output "Tool calls: [...]" in the text, but we'll parse and execute them separately
        assistant_content_clean = assistant_content
        # Remove "Tool calls:" and JSON arrays from the text
        assistant_content_clean = re.sub(r'Tool calls?\s*:\s*\[.*?\]', '', assistant_content_clean, flags=re.DOTALL)
        assistant_content_clean = re.sub(r'\{\s*"tool_calls"\s*:\s*\[.*?\]\s*\}', '', assistant_content_clean, flags=re.DOTALL)
        # Remove standalone JSON tool call objects
        assistant_content_clean = re.sub(r'\{\s*"id"\s*:\s*"[^"]+"\s*,\s*"type"\s*:\s*"function"\s*,\s*"function"\s*:\s*\{[^}]+\}\s*\}', '', assistant_content_clean, flags=re.DOTALL)
        assistant_content_clean = assistant_content_clean.strip()
        
        # Use cleaned content for display
        assistant_content = assistant_content_clean
        
        # Add assistant message
        assistant_msg = {
            "role": "assistant",
            "content": assistant_content
        }
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        conversation_messages.append(assistant_msg)
        
        if verbose:
            print(f"\n[Iteration {iteration}] Assistant response:")
            print(assistant_content[:500] + "..." if len(assistant_content) > 500 else assistant_content)
            if tool_calls:
                print(f"\n[Iteration {iteration}] Detected {len(tool_calls)} tool call(s):")
                for i, call in enumerate(tool_calls, 1):
                    func_name = call.get("function", {}).get("name", "unknown")
                    print(f"  {i}. {func_name}")
            else:
                print(f"\n[Iteration {iteration}] ⚠️  No tool calls detected in response")
                print(f"   Looking for: JSON tool_calls, function patterns, or tool call syntax")
        
        # If no tool calls, try to infer from natural language
        if not tool_calls:
            # Check if the model is describing a file operation
            content_lower = assistant_content.lower()
            
            # Look for file creation patterns
            if any(phrase in content_lower for phrase in ["create", "new file", "write a file", "create a file"]):
                # Try to extract file path from user message or assistant response
                file_path = None
                # Check user message for file path
                for msg in conversation_messages:
                    if msg.get("role") == "user":
                        user_msg = msg.get("content", "")
                        # Extract path from user message - be more flexible
                        # Look for patterns like "file named X", "file at X", "create X"
                        path_match = re.search(r'(?:file\s+(?:named|at|called)\s+)?(?:`)?([^\s`]+\.\w+)(?:`)?', user_msg, re.IGNORECASE)
                        if not path_match:
                            # Try simpler pattern: just filename with extension
                            path_match = re.search(r'(\w+\.\w+)', user_msg)
                        if path_match:
                            file_path = path_match.group(1)
                            break
                
                if file_path:
                    # For file creation, check if user specified content
                    # If not, create empty file (don't infer content)
                    contents = ""
                    user_msg = ""
                    for msg in conversation_messages:
                        if msg.get("role") == "user":
                            user_msg = msg.get("content", "")
                            break
                    
                    user_msg_lower = user_msg.lower()
                    
                    # Only add content if explicitly requested with quotes or specific phrasing
                    if "with content" in user_msg_lower or "containing" in user_msg_lower or "add the content" in user_msg_lower:
                        # Try to extract content from user message - look for quoted content
                        # Pattern: "content 'text'" or "content \"text\"" or "add the content 'text'"
                        content_match = re.search(r"(?:content|text|with)\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                        if not content_match:
                            # Try: "add the content 'text'"
                            content_match = re.search(r"add\s+the\s+content\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                        if content_match:
                            contents = content_match.group(1)
                    
                    # Infer write_file call
                    import uuid
                    tool_calls.append({
                        "id": f"call_{uuid.uuid4().hex[:12]}",
                        "type": "function",
                        "function": {
                            "name": "write_file",
                            "arguments": json.dumps({
                                "path": file_path,
                                "contents": contents
                            })
                        }
                    })
                    if verbose:
                        print(f"\n[Iteration {iteration}] ⚠️  Inferred tool call from natural language:")
                        print(f"   Detected file creation intent, inferred write_file for: {file_path}")
                        if contents:
                            print(f"   With content: {contents[:50]}...")
                        else:
                            print(f"   Empty file (no content specified)")
            
            # Look for "add content" patterns - need to read file first, then modify
            elif "add" in content_lower and ("content" in content_lower or "text" in content_lower):
                # Extract file path and content from user message
                file_path = None
                content_to_add = ""
                for msg in conversation_messages:
                    if msg.get("role") == "user":
                        user_msg = msg.get("content", "")
                        # Extract file path - look for "to the file X" or "file X"
                        path_match = re.search(r'(?:to\s+the\s+file|file)\s+(?:`)?([^\s`]+\.\w+)(?:`)?', user_msg, re.IGNORECASE)
                        if not path_match:
                            # Try simpler: just filename
                            path_match = re.search(r'(\w+\.\w+)', user_msg)
                        if path_match:
                            file_path = path_match.group(1)
                        # Extract content to add - look for quoted content
                        content_match = re.search(r"(?:content|text)\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                        if not content_match:
                            # Try: "add the content 'text'"
                            content_match = re.search(r"add\s+the\s+content\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                        if not content_match:
                            # Try any quoted string
                            content_match = re.search(r"['\"]([^'\"]+)['\"]", user_msg)
                        if content_match:
                            content_to_add = content_match.group(1)
                        break
                
                if file_path:
                    # Need to read file first, then add content
                    import uuid
                    read_call_id = f"call_{uuid.uuid4().hex[:12]}"
                    tool_calls.append({
                        "id": read_call_id,
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": file_path})
                        }
                    })
                    if verbose:
                        print(f"\n[Iteration {iteration}] ⚠️  Inferred tool call from natural language:")
                        print(f"   Detected 'add content' intent, will read {file_path} first")
                        if content_to_add:
                            print(f"   Content to add: '{content_to_add}'")
                        print(f"   (Next iteration will add content to file)")
            
            # Look for file reading patterns
            elif any(phrase in content_lower for phrase in ["read", "open the file", "read the file"]):
                # Try to extract file path
                file_path = None
                for msg in conversation_messages:
                    if msg.get("role") == "user":
                        user_msg = msg.get("content", "")
                        path_match = re.search(r'(?:file|at|path)\s+(?:`)?([^\s`]+\.\w+)(?:`)?', user_msg, re.IGNORECASE)
                        if path_match:
                            file_path = path_match.group(1)
                            break
                
                if file_path:
                    import uuid
                    tool_calls.append({
                        "id": f"call_{uuid.uuid4().hex[:12]}",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": json.dumps({"path": file_path})
                        }
                    })
                    if verbose:
                        print(f"\n[Iteration {iteration}] ⚠️  Inferred tool call from natural language:")
                        print(f"   Detected file reading intent, inferred read_file for: {file_path}")
        
        # If no tool calls, check if we just read a file and user wants to add content
        # In that case, we should infer a write_file call
        if not tool_calls:
            # Check if last tool response was a file read and user wants to add content
            if conversation_messages and len(conversation_messages) > 0:
                # Find the most recent tool response (file read)
                last_tool_msg = None
                last_user_msg = None
                file_path_from_read = None
                
                # Find last tool response and the read_file call that generated it
                for i in range(len(conversation_messages) - 1, -1, -1):
                    msg = conversation_messages[i]
                    if msg.get("role") == "tool" and last_tool_msg is None:
                        last_tool_msg = msg
                        # Find the corresponding read_file call
                        tool_call_id = msg.get("tool_call_id", "")
                        # Look backwards for the assistant message with this tool_call_id
                        for j in range(i - 1, -1, -1):
                            prev_msg = conversation_messages[j]
                            if prev_msg.get("role") == "assistant" and "tool_calls" in prev_msg:
                                for call in prev_msg.get("tool_calls", []):
                                    if call.get("id") == tool_call_id and call.get("function", {}).get("name") == "read_file":
                                        try:
                                            args = json.loads(call.get("function", {}).get("arguments", "{}"))
                                            file_path_from_read = args.get("path", "")
                                        except:
                                            pass
                                        break
                            if file_path_from_read:
                                break
                    if msg.get("role") == "user" and last_user_msg is None:
                        last_user_msg = msg
                    if last_tool_msg and last_user_msg:
                        break
                
                # If we have a tool response (file read) and user wants to add content
                if last_tool_msg and last_user_msg and file_path_from_read:
                    user_msg = last_user_msg.get("content", "")
                    user_msg_lower = user_msg.lower()
                    
                    if "add" in user_msg_lower and ("content" in user_msg_lower or "text" in user_msg_lower or "line" in user_msg_lower):
                        # Extract content to add from user message
                        content_to_add = ""
                        content_match = re.search(r"(?:content|text|line)\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                        if not content_match:
                            content_match = re.search(r"['\"]([^'\"]+)['\"]", user_msg)
                        if content_match:
                            content_to_add = content_match.group(1)
                        
                        # Get existing file content from tool response
                        existing_content = last_tool_msg.get("content", "")
                        if not existing_content.startswith("Error") and content_to_add:
                            # Append or prepend content based on user intent
                            if "prepend" in user_msg_lower or "beginning" in user_msg_lower or "start" in user_msg_lower:
                                new_content = content_to_add + "\n" + existing_content if existing_content else content_to_add
                            else:
                                # Default: append
                                new_content = existing_content + "\n" + content_to_add if existing_content else content_to_add
                            
                            # Infer write_file call
                            import uuid
                            tool_calls.append({
                                "id": f"call_{uuid.uuid4().hex[:12]}",
                                "type": "function",
                                "function": {
                                    "name": "write_file",
                                    "arguments": json.dumps({
                                        "path": file_path_from_read,
                                        "contents": new_content
                                    })
                                }
                            })
                            if verbose:
                                print(f"\n[Iteration {iteration}] ⚠️  Inferred write_file from context:")
                                print(f"   File was read, user wants to add content, inferring write_file")
                                print(f"   Adding '{content_to_add}' to {file_path_from_read}")
                            else:
                                print(f"\n⚠️  Model didn't generate write_file, inferring from context...")
        
        # If still no tool calls, we're done
        if not tool_calls:
            if verbose:
                print(f"\n[Iteration {iteration}] No tool calls detected. Finalizing response.")
                print(f"   Model said: {assistant_content[:200]}")
                print(f"   This might mean the model needs more training or different prompting.")
            return conversation_messages, assistant_content
        
        # Update assistant message with inferred tool calls
        if tool_calls and "tool_calls" not in assistant_msg:
            assistant_msg["tool_calls"] = tool_calls
        
        # Execute tool calls
        if tool_calls:
            if verbose:
                print(f"\n[Iteration {iteration}] Executing {len(tool_calls)} tool call(s)...")
            else:
                # Even without verbose, show that we're executing tools
                print(f"\n🔧 Executing {len(tool_calls)} tool call(s)...")
        
        for tool_call in tool_calls:
            func_name = tool_call.get("function", {}).get("name", "")
            func_args = tool_call.get("function", {}).get("arguments", "{}")
            
            if verbose:
                try:
                    args = json.loads(func_args)
                    if func_name == "read_file":
                        print(f"  - {func_name}(path='{args.get('path', '')}')")
                    elif func_name == "write_file":
                        path = args.get("path", "")
                        contents = args.get("contents", "")
                        contents_preview = contents[:50] if len(contents) > 50 else contents
                        print(f"  - {func_name}(path='{path}', contents_length={len(contents)} chars)")
                        if contents:
                            print(f"    Preview: {contents_preview}...")
                        else:
                            print(f"    (empty file)")
                    else:
                        print(f"  - {func_name}({func_args})")
                except:
                    print(f"  - {func_name}({func_args})")
            else:
                # Non-verbose: just show what we're doing
                try:
                    args = json.loads(func_args)
                    if func_name == "write_file":
                        path = args.get("path", "")
                        print(f"  Writing to {path}...")
                    elif func_name == "read_file":
                        path = args.get("path", "")
                        print(f"  Reading {path}...")
                except:
                    pass
            
            result, error = execute_tool_call(tool_call)
            
            if error:
                result = error
                if verbose:
                    print(f"    ❌ Error: {error}")
                else:
                    print(f"    ❌ Error: {error}")
            else:
                if verbose:
                    result_preview = result[:100] + "..." if len(result) > 100 else result
                    print(f"    ✅ Result: {result_preview}")
                elif func_name == "write_file":
                    print(f"    ✅ File written successfully")
                elif func_name == "read_file":
                    print(f"    ✅ File read ({len(result)} chars)")
            
            # Special handling: if we read a file and user wants to add content, we may need to help
            # Store context for next iteration
            if func_name == "read_file" and not error:
                # Store the file path and content for potential write operation
                file_path = ""
                try:
                    args = json.loads(func_args)
                    file_path = args.get("path", "")
                except:
                    pass
                
                # Check if user wants to add content
                user_intent = None
                content_to_add = ""
                for msg in conversation_messages:
                    if msg.get("role") == "user":
                        user_msg = msg.get("content", "")
                        user_msg_lower = user_msg.lower()
                        if "add" in user_msg_lower and ("content" in user_msg_lower or "text" in user_msg_lower or "line" in user_msg_lower):
                            user_intent = "add_content"
                            # Extract content to add
                            content_match = re.search(r"(?:content|text|line)\s+['\"]([^'\"]+)['\"]", user_msg, re.IGNORECASE)
                            if not content_match:
                                content_match = re.search(r"['\"]([^'\"]+)['\"]", user_msg)
                            if content_match:
                                content_to_add = content_match.group(1)
                            break
                
                # Store this for next iteration
                if user_intent == "add_content" and file_path and content_to_add:
                    # We'll check in the next iteration if model generates write_file
                    # If not, we can infer it
                    pass
            
            # Add tool response
            conversation_messages.append({
                "role": "tool",
                "content": result,
                "tool_call_id": tool_call.get("id", "")
            })
        
        # Continue conversation (model will see tool responses and generate next step)
        # This will loop back to generate again
    
    # Max iterations reached
    return conversation_messages, assistant_content


def get_system_prompt_with_tools(mode: str = "generic") -> str:
    """Get system prompt that includes tool information.
    
    Args:
        mode: "generic" for file operations only, "rego" for Rego-specific editing
    """
    if mode == "generic":
        # Generic file operations prompt (matches training data)
        return """Your job is to edit files using tools exactly as the user instructs.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

Guidelines:
- Do not infer missing logic
- Do not create domain-specific content
- Only manipulate the text the user describes
- Follow the user's instructions precisely
- Use tools to read, modify, and write files
- If a file doesn't exist, use write_file to create it"""
    
    else:
        # Rego-specific prompt (for domain-specific editing)
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

## File Editing Guidelines

When adding a new rule to an existing policy file:
1. First, read the existing file using the read_file tool
2. Keep the existing package declaration and imports
3. Add the new rule after existing deny rules
4. Place helper rules (starting with _) after all deny rules
5. Maintain proper formatting and spacing
6. Include METADATA annotations for the new rule
7. Preserve all existing rules and helpers
8. Save the updated file using the write_file tool

## Available Tools

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

When you need to read or write a file, make a tool call. The system will execute it and provide the result.

Write Rego deny rules that check the attestation structure."""


def main():
    parser = argparse.ArgumentParser(
        description="Run inference with fine-tuned Qwen3 model supporting tool calls"
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
        help="User prompt (natural language instruction)"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=3072,
        help="Maximum input length (default: 3072)"
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
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose output including tool execution"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum tool call iterations (default: 10)"
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="generic",
        choices=["generic", "rego"],
        help="System prompt mode: 'generic' for file operations only, 'rego' for Rego-specific editing (default: generic)"
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
        print("Interactive mode with tool support - Enter prompts (type 'quit' to exit)")
        print("=" * 70)
        
        while True:
            try:
                prompt = input("\n> ")
                if prompt.lower() in ['quit', 'exit', 'q']:
                    break
                
                if not prompt.strip():
                    continue
                
                messages = [
                    {"role": "system", "content": get_system_prompt_with_tools(args.mode)},
                    {"role": "user", "content": prompt},
                ]
                
                final_messages, final_response = generate_with_tools(
                    model, tokenizer, messages,
                    max_length=args.max_length,
                    temperature=args.temperature,
                    top_p=args.top_p,
                    max_iterations=args.max_iterations,
                    verbose=args.verbose,
                )
                
                print("\n" + "=" * 70)
                print("Final Response:")
                print("=" * 70)
                print(final_response)
                print("=" * 70)
                
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
    
    messages = [
        {"role": "system", "content": get_system_prompt_with_tools(args.mode)},
        {"role": "user", "content": args.prompt},
    ]
    
    print("Generating response with tool support...")
    print("=" * 70)
    
    final_messages, final_response = generate_with_tools(
        model, tokenizer, messages,
        max_length=args.max_length,
        temperature=args.temperature,
        top_p=args.top_p,
        max_iterations=args.max_iterations,
        verbose=args.verbose,
    )
    
    print("\n" + "=" * 70)
    print("Final Response:")
    print("=" * 70)
    # Only show response if it's not just tool execution confirmation
    if final_response and len(final_response.strip()) > 10:
        print(final_response)
    else:
        print("(Tool operations completed)")
    print("=" * 70)
    
    # Show tool execution summary if verbose
    if args.verbose:
        tool_count = sum(1 for msg in final_messages if "tool_calls" in msg)
        print(f"\nTool calls made: {tool_count}")


if __name__ == "__main__":
    main()
