#!/usr/bin/env python3
"""
LangChain-based inference with tool support.

This demonstrates how to use LangChain for tool calling, but note:
- LangChain still requires the model to generate tool calls correctly
- For small models that don't generate structured tool calls, this may not help
- Better suited for models with native function calling support (OpenAI, Anthropic)
"""

import argparse
import sys
from pathlib import Path

try:
    from langchain.tools import tool
    from langchain.agents import create_agent
    from langchain_core.messages import HumanMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("Error: langchain not found. Install with: pip install langchain langchain-core")
    sys.exit(1)

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Error: transformers not found. Install with: pip install transformers torch")
    sys.exit(1)


# Define tools using LangChain's @tool decorator
@tool
def read_file(path: str) -> str:
    """Read the contents of a file at the given path.
    
    Args:
        path: The path to the file to read
    """
    try:
        file_path = Path(path)
        if not file_path.exists():
            return f"Error: File not found: {path}"
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tool
def write_file(path: str, contents: str) -> str:
    """Write contents to a file at the given path.
    
    Args:
        path: The path to the file to write
        contents: The contents to write to the file
    """
    try:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(contents)
        return "File written successfully."
    except Exception as e:
        return f"Error writing file: {str(e)}"


def create_langchain_agent(model_path: str, model_type: str = "huggingface"):
    """
    Create a LangChain agent with file operation tools.
    
    Args:
        model_path: Path to the model
        model_type: Type of model ("huggingface" or "openai")
    """
    tools = [read_file, write_file]
    
    if model_type == "huggingface":
        # For HuggingFace models, we need to wrap them in a LangChain LLM
        try:
            from langchain_community.llms import HuggingFacePipeline
            from transformers import pipeline
            
            device = "cuda" if torch.cuda.is_available() else "cpu"
            print(f"Loading model from {model_path}...")
            print(f"Using device: {device}")
            
            tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            model = AutoModelForCausalLM.from_pretrained(
                model_path,
                trust_remote_code=True,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map="auto" if device == "cuda" else None,
            )
            if device == "cpu":
                model = model.to(device)
            model.eval()
            
            # Create pipeline
            pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                max_new_tokens=512,
                temperature=0.7,
                do_sample=True,
                return_full_text=False,
            )
            
            llm = HuggingFacePipeline(pipeline=pipe)
            
        except ImportError:
            print("Error: langchain_community not found. Install with: pip install langchain-community")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)
    
    elif model_type == "openai":
        # For OpenAI models (if you have API access)
        try:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.7)
        except ImportError:
            print("Error: langchain-openai not found. Install with: pip install langchain-openai")
            sys.exit(1)
    
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    # Create agent
    system_prompt = """You are a helpful assistant that can read and write files.
    
When the user asks you to:
- Create a file: Use write_file with the file path and contents
- Read a file: Use read_file with the file path
- Add content to a file: First read the file, then write it back with the new content appended
- Edit a file: First read the file, make the changes, then write it back

Follow the user's instructions precisely. Do not infer content unless explicitly asked."""
    
    agent = create_agent(
        llm,
        tools=tools,
        system_prompt=system_prompt,
    )
    
    return agent


def main():
    parser = argparse.ArgumentParser(
        description="LangChain-based inference with tool support"
    )
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to model (for HuggingFace) or model name (for OpenAI)"
    )
    parser.add_argument(
        "--model-type",
        type=str,
        default="huggingface",
        choices=["huggingface", "openai"],
        help="Type of model to use"
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
    
    # Create agent
    agent = create_langchain_agent(args.model, args.model_type)
    print("Agent created successfully!\n")
    
    # Interactive mode
    if args.interactive:
        print("LangChain Agent - Enter prompts (type 'quit' to exit)")
        print("=" * 70)
        print("\nExamples:")
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
                
                # Invoke agent
                result = agent.invoke({
                    "messages": [HumanMessage(content=prompt)]
                })
                
                print(f"\n{result['messages'][-1].content}")
                
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
    
    result = agent.invoke({
        "messages": [HumanMessage(content=args.prompt)]
    })
    
    print(result['messages'][-1].content)


if __name__ == "__main__":
    main()
