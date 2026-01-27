# Tool Calling Issues and Solutions

## The Problem

The model is generating **text descriptions** of tool calls instead of **structured tool calls** that can be executed.

### What's Happening

**Training Data Format:**
```json
{
  "role": "assistant",
  "content": "I'll read the file...",
  "tool_calls": [
    {
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "read_file",
        "arguments": "{\"path\": \"file.txt\"}"
      }
    }
  ]
}
```

**Model Output:**
```
I'll read the file, make the requested changes, and save it.

Tool calls:
[
  {
    "id": "call_abc123",
    "type": "function",
    "function": {
      "name": "read_file",
      "arguments": "{\"path\": \"file.txt\"}"
    }
  }
]
```

The model is **embedding tool calls in the text** instead of generating them as structured data.

## Root Causes

### 1. Model Architecture Limitation

**Text generation models** (like Qwen) generate **sequences of tokens**, not structured data. They can learn patterns but:
- Tool calls are structured JSON, not natural text
- The model sees tool calls in training but generates them as text
- Parsing text to extract JSON is error-prone

### 2. Training Data Format Mismatch

The training data has `tool_calls` as a **separate key** in the message object, but:
- During generation, the model only outputs text
- There's no mechanism to output structured `tool_calls` separately
- The model learns to describe tool calls in text format

### 3. Small Model Limitations

Small models (<3B parameters) struggle with:
- Complex structured output
- Multi-step reasoning (read → modify → write)
- Consistent tool call formatting

## Solutions

### Option 1: Use LangChain (Recommended for Production)

**LangChain** provides:
- Built-in tool calling support
- Structured output parsing
- Retry logic and error handling
- Better integration with LLMs that support function calling

**Pros:**
- ✅ Handles tool calling more reliably
- ✅ Better error handling
- ✅ Retry logic
- ✅ Works with models that support function calling APIs

**Cons:**
- ❌ Adds dependency
- ❌ May not work well with small fine-tuned models
- ❌ Still requires model to generate tool calls correctly

**Example:**
```python
from langchain.agents import initialize_agent, Tool
from langchain.llms import HuggingFacePipeline

# Define tools
tools = [
    Tool(
        name="read_file",
        func=read_file_tool,
        description="Read a file at the given path"
    ),
    Tool(
        name="write_file",
        func=write_file_tool,
        description="Write contents to a file at the given path"
    )
]

# Initialize agent
agent = initialize_agent(
    tools,
    llm,
    agent="zero-shot-react-description",
    verbose=True
)

# Use agent
agent.run("Create a file named hey.rego")
```

### Option 2: Improve Training Data Format

**Problem:** Model generates text, not structured tool calls.

**Solution:** Train model to output tool calls in a **parseable text format**:

```
<tool_call>
read_file("file.txt")
</tool_call>
```

Or use a structured output format that's easier to parse:
```
TOOL_CALL: read_file
ARGUMENTS: {"path": "file.txt"}
```

### Option 3: Use a Model with Native Function Calling

**Models with native function calling:**
- OpenAI GPT-4, GPT-3.5-turbo
- Anthropic Claude
- Some newer open-source models

These models have built-in support for structured tool calls.

### Option 4: Post-Process with Structured Output

Use a separate step to convert model text to structured tool calls:
1. Model generates natural language description
2. Use a parser/LLM to extract tool calls
3. Execute tool calls

### Option 5: Two-Stage Approach

1. **Stage 1:** Model generates plan in natural language
2. **Stage 2:** Simple parser extracts actions and executes them

## Recommendation

### For Your Use Case (Small Model, File Operations)

**Best Approach:** Use **LangChain with a better base model** or **improve the training data format**.

**Why:**
1. Small models struggle with structured output
2. LangChain provides better tool integration
3. But LangChain still needs the model to generate tool calls correctly

**Alternative:** Accept that the model generates text descriptions and use a **deterministic parser** to:
1. Parse user intent from model text
2. Extract file paths and content
3. Execute operations directly

This is essentially what the inference script is trying to do with natural language inference, but it's brittle.

## Immediate Fix: Better Inference Logic

Instead of relying on the model to generate tool calls, make the inference script **smarter**:

1. **Parse user intent** directly (not from model output)
2. **Execute operations** based on user request
3. **Use model** only for content generation (what to write)

This separates concerns:
- **User → Script:** Parse intent, execute operations
- **User → Model:** Generate content (rules, code, etc.)

## Conclusion

**The problem is both:**
- **Model:** Small models struggle with structured tool calling
- **Approach:** Text generation models aren't ideal for tool calling

**LangChain would help** if:
- You use a model with native function calling support
- Or you're okay with the model generating text that LangChain parses

**Better solution for your case:**
- Use the model for **content generation** (rules, code)
- Use **deterministic logic** for **file operations** (read, write)
- Combine them: Model generates content → Script handles file I/O

This is essentially the **two-model approach** we discussed earlier, but with a simpler file operations layer.
