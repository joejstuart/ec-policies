# File Edit Workflow

## Key Principle: THE LLM DOES NOT EDIT FILES

At no point does the LLM ever:
- open a file handle
- write bytes
- diff code
- resolve file paths
- apply patches
- or even verify the final modification

**The LLM never touches the filesystem.**

The LLM only produces instructions or structured tool calls that are carried out by deterministic tools.

## 🔧 So what actually happens? (Correct workflow)

Let's walk through what really happens under the hood in a system like Claude Code or Cursor.

Imagine you say:
> "Update foo.go so that the function returns an error when input is empty."

### Step 1 — The LLM predicts which tool to call

It outputs something like:

```xml
<tool_call>
<function=read_file>
<parameter=path>
foo.go
</parameter>
</function>
</tool_call>
```

### Step 2 — Runtime executes the tool (deterministically)

The orchestrator reads the file from disk.

It produces a tool response containing the file contents:

```xml
<tool_response>
```go
package main

func Handle(input string) string {
    return "OK"
}
```
</tool_response>
```

### Step 3 — The LLM now "sees" the file content

The LLM has *no direct filesystem access*.

It only sees:
- The user instruction  
- The system rules  
- The tool response containing the file text  

**This is the moment reasoning occurs.**

The LLM reads the file text and decides:
- What to change  
- Where  
- Whether it needs more context  

It writes **new file content** as plain text.

### Step 4 — The LLM issues another tool call

Example:

```xml
<tool_call>
<function=write_file>
<parameter=path>
foo.go
</parameter>
<parameter=contents>
package main

func Handle(input string) (string, error) {
    if input == "" {
        return "", errors.New("empty input")
    }
    return "OK", nil
}
</parameter>
</function>
</tool_call>
```

**Notice:**
- LLM does NO diffing
- LLM generates the entire new file from scratch
- The actual write operation is offloaded to the deterministic tool

### Step 5 — Runtime performs the actual write

No LLM involvement.

File gets overwritten (or patch applied, depending on your tool)

Runtime may send back a success message like:

```xml
<tool_response>
File written successfully.
</tool_response>
```

## 🧠 What the LLM actually does

The LLM:
1. **Plans** - "User wants to modify foo.go. I must read it first."
2. **Requests state** - Using read_file.
3. **Reads state** - Uses the returned content to infer the update.
4. **Generates the updated content** - As a whole buffer or as a structured patch — depending on your design.
5. **Produces a tool call to save it** - The LLM does not perform the write.

## 🔒 What the deterministic tools handle

Deterministic tools handle everything risky:
- ✔ Reading files
- ✔ Writing files
- ✔ Directory traversal
- ✔ Permissions
- ✔ Patching / merging / diffing
- ✔ Serialization
- ✔ Error handling
- ✔ Preventing hallucinated paths
- ✔ Preventing hallucinated filesystem operations
- ✔ Avoiding destructive behavior

This is exactly how safety is maintained:
- The LLM can "suggest" anything.
- But only valid suggestions routed through controlled tools can modify your system.

## 🔍 Why does it work this way?

Because LLMs:
- hallucinate
- are non-deterministic
- cannot be trusted with IO
- cannot safely manipulate files directly
- cannot guarantee that generated patches apply cleanly
- may add extra whitespace, BOMs, or encoding artifacts

**Deterministic tools guarantee consistency.**

## 🧩 What this means for your training data

### Track A (your generic tool dataset)

Teaches:
- How to call tools
- How to sequence them
- How to manipulate text
- How to "think" like Claude Code

### Track B (your Rego-generation dataset)

Teaches:
- How to generate Rego code
- Metadata rules
- Helpers
- etc.

### Track C (combined dataset, only when needed)

Teaches:
- When to combine file-editing behavior with domain reasoning

**This separation prevents mode collapse.**

## 🚦 Summary (print this out)

### 🟦 The LLM:
- interprets instructions
- requests file content via tool call
- generates modified file as plain text
- instructs the runtime to write it

### 🟩 The deterministic runtime:
- reads the file
- writes the file
- validates paths
- enforces safety
- maintains filesystem integrity

### 🟥 The LLM NEVER:
- touches the filesystem directly
- edits files in-place
- applies diffs
- navigates directories
- validates file paths
- writes bytes to disk
