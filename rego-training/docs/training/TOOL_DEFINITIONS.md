# Tool Definitions for File Editing

This document explains how tool definitions work with the file editing training and what needs to be provided at inference time.

## How Tool Training Works

The model learns:
- **Tool names** (`read_file`, `write_file`)
- **Parameter names** (`path`, `contents`)
- **Calling format** (XML-style tool calls)
- **Workflow** (read → edit → write)

The model does **NOT** learn:
- Which binary/executable to use
- How to implement the tools
- File system operations

## Tool Definitions at Inference Time

When using the tool-based model, you must provide tool definitions at inference time. The inference system (like Cursor, Ollama, or your custom inference server) maps tool calls to actual implementations.

### Example Tool Definitions

Here's what tool definitions should look like (format depends on your inference system):

#### For OpenAI-Compatible APIs

```json
{
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "read_file",
        "description": "Read the contents of a file at the given path",
        "parameters": {
          "type": "object",
          "properties": {
            "path": {
              "type": "string",
              "description": "The path to the file to read"
            }
          },
          "required": ["path"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "write_file",
        "description": "Write contents to a file at the given path",
        "parameters": {
          "type": "object",
          "properties": {
            "path": {
              "type": "string",
              "description": "The path to the file to write"
            },
            "contents": {
              "type": "string",
              "description": "The contents to write to the file"
            }
          },
          "required": ["path", "contents"]
        }
      }
    }
  ]
}
```

#### For Cursor/Function Calling Format

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read the contents of a file at the given path",
      "parameters": {
        "type": "object",
        "properties": {
          "path": {
            "type": "string",
            "description": "The path to the file to read"
          }
        },
        "required": ["path"]
      }
    },
    {
      "name": "write_file",
      "description": "Write contents to a file at the given path",
      "parameters": {
        "type": "object",
        "properties": {
          "path": {
            "type": "string",
            "description": "The path to the file to write"
          },
          "contents": {
            "type": "string",
            "description": "The contents to write to the file"
          }
        },
        "required": ["path", "contents"]
      }
    }
  ]
}
```

## Tool Implementation

The inference system must provide implementations that:

1. **Parse tool calls** from the model's response
2. **Execute the tool** (read/write files)
3. **Return results** to the model

### Example Implementation (Python)

```python
def read_file(path: str) -> str:
    """Read file and return contents."""
    with open(path, 'r') as f:
        return f.read()

def write_file(path: str, contents: str) -> None:
    """Write contents to file."""
    with open(path, 'w') as f:
        f.write(contents)
    return "File written successfully."

# Tool handler
def handle_tool_call(tool_name: str, arguments: dict):
    if tool_name == "read_file":
        return read_file(arguments["path"])
    elif tool_name == "write_file":
        return write_file(arguments["path"], arguments["contents"])
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
```

## Training vs Inference

### During Training

The training examples show:
- Tool names and parameters
- Expected tool call format
- Tool responses
- Workflow patterns

**No implementation is needed** - the model just learns the interface.

### During Inference

You must provide:
1. **Tool definitions** (names, parameters, descriptions)
2. **Tool implementations** (actual code that reads/writes files)
3. **Tool execution** (parse calls, execute, return results)

## Integration with Inference Systems

### Cursor

Cursor automatically provides file I/O tools. The model will use:
- `read_file` - Already available in Cursor
- `write_file` - Already available in Cursor

No additional setup needed if using Cursor's inference.

### Ollama

Ollama supports function calling but requires:
1. Tool definitions in the request
2. Custom tool execution handler
3. Tool results returned in the response

### Custom Inference Server

You need to:
1. Parse tool calls from model responses
2. Execute tools based on tool name
3. Return tool results to the model
4. Continue the conversation with tool results

## Tool Call Format

The model learns to use this format (from training):

```
<tool_call>
<function=read_file>
<parameter=path>
policy/release/tasks/tasks.rego
</parameter>
</function>
</tool_call>
```

Your inference system must:
1. Parse this format
2. Extract function name and parameters
3. Execute the tool
4. Return results in `<tool_response>` format

## Summary

- **Training**: Model learns tool names, parameters, and calling format
- **Inference**: You provide tool definitions and implementations
- **Execution**: Your system executes tools and returns results
- **No binaries needed**: The model doesn't know about binaries - it just calls tools by name

The model is like a programmer who knows the API but doesn't need to know the implementation details.
