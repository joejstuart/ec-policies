#!/usr/bin/env python3
"""
Generate generic tool usage training data (Track A).

This teaches the model pure tool usage behavior:
- How to read files with tools
- How to modify content
- How to write files back
- WITHOUT domain-specific reasoning
- WITHOUT Rego/attestation knowledge
- Just procedural correctness

This creates the behavioral scaffold before adding domain knowledge.
"""

import json
import random
import uuid
from pathlib import Path
from typing import Dict, List


def create_simple_file_edit_example(
    file_path: str,
    original_content: str,
    modified_content: str,
    edit_description: str
) -> Dict:
    """Create a simple file editing example with tool usage."""
    
    import uuid
    
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**IMPORTANT**: You do NOT directly edit files. You generate tool calls that the system executes.

## CORRECT WORKFLOW (CRITICAL):

1. **Read the file first**: Generate a read_file tool call to get the current file content
2. **Reason about changes**: Look at the file content (from tool response) and understand what needs to change
3. **Generate COMPLETE file content**: Create the entire new file content as text (NOT a diff or patch)
4. **Write the complete file**: Generate a write_file tool call with the complete new file content

The system will execute your tool calls. You never touch the filesystem directly.

## CRITICAL GUIDELINES:

- **ALWAYS generate the COMPLETE file content** in write_file, not just the changes
- **NEVER generate diffs, patches, or partial content** - always the full file
- Do NOT infer or generate content based on file extensions
- Do NOT create new content that wasn't in the original file
- Do NOT "fix" or "improve" the file content
- Do NOT add domain-specific logic or code
- ONLY perform the exact text manipulation the user requests
- If the user says "replace X with Y", ONLY replace X with Y - nothing else
- If the user says "add the content 'X'", add ONLY 'X' - nothing else
- If the file is EMPTY and user says "add content 'X'", the file should contain ONLY 'X' (no other content)
- Do NOT add example content like "line1: first line" or "existing content" unless it's already in the file
- Content to add/remove is usually specified in single or double quotes: 'text' or "text"
- Extract the exact content from quotes - do not modify or interpret it
- When reading a file, use ONLY the content that's actually in the file (from read_file tool response)
- Do NOT infer or add content that wasn't in the file you read
- Preserve all other content exactly as it was (if any exists)
- Follow the user's instructions precisely and literally
- Generate tool calls (read_file, write_file) that the system will execute
- You never directly access or modify files - only generate tool calls and content"""
    
    user_prompt = f"""Edit the file at `{file_path}`.

{edit_description}"""
    
    # Generate unique IDs for tool calls (for tool response matching)
    read_call_id = f"call_{uuid.uuid4().hex[:12]}"
    write_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    # Embed tool calls in assistant content text (parseable format)
    assistant_content = f"""I'll read the file, make the requested changes, and save it.

<tool_call>
name: read_file
arguments: {json.dumps({"path": file_path})}
</tool_call>"""
    
    tool_response_1_content = original_content
    
    assistant_content_2 = f"""Now I'll generate the complete updated file content and save it.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": modified_content
})}
</tool_call>"""
    
    tool_response_2_content = """File written successfully."""
    
    assistant_content_3 = """Done."""
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
                # Note: We keep tool_calls for backward compatibility, but the model should learn from content
            },
            {
                "role": "tool",
                "content": tool_response_1_content,
                "tool_call_id": read_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            },
            {
                "role": "tool",
                "content": tool_response_2_content,
                "tool_call_id": write_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_3
            }
        ]
    }


def create_line_replacement_example(file_path: str) -> Dict:
    """Create example: Replace specific lines."""
    original = """Line 1: First line
Line 2: Second line
Line 3: Third line
Line 4: Fourth line
Line 5: Fifth line"""
    
    modified = """Line 1: First line
Line 2: Second line
Line 3: Updated third line
Line 4: Updated fourth line
Line 5: Fifth line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace lines 3-4 with:\nLine 3: Updated third line\nLine 4: Updated fourth line"
    )


def create_insertion_example(file_path: str) -> Dict:
    """Create example: Insert lines."""
    original = """Line 1: First line
Line 2: Second line
Line 3: Third line"""
    
    modified = """Line 1: First line
Line 2: Second line
Line 2.5: Inserted line
Line 3: Third line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Insert a new line after line 2: 'Line 2.5: Inserted line'"
    )


def create_deletion_example(file_path: str) -> Dict:
    """Create example: Delete lines."""
    original = """Line 1: First line
Line 2: Second line
Line 3: Third line
Line 4: Fourth line"""
    
    modified = """Line 1: First line
Line 2: Second line
Line 4: Fourth line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Delete line 3"
    )


def create_text_replacement_example(file_path: str) -> Dict:
    """Create example: Replace text."""
    # Use simple, generic content that doesn't suggest any domain
    original = """This is a sample file.
It contains some text.
We need to replace 'sample' with 'example'.
The file has multiple lines."""
    
    modified = """This is an example file.
It contains some text.
We need to replace 'sample' with 'example'.
The file has multiple lines."""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace all occurrences of 'sample' with 'example'"
    )


def create_simple_word_replacement_example(file_path: str) -> Dict:
    """Create example: Simple word replacement (emphasizes no content inference)."""
    # Use very simple content to emphasize text-only manipulation
    original = """stuff
more stuff
even more stuff"""
    
    modified = """blah
more blah
even more blah"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace the word 'stuff' with 'blah'"
    )


def create_word_replacement_preserve_structure_example(file_path: str) -> Dict:
    """Create example: Word replacement that preserves file structure exactly."""
    # Use content that looks like code but emphasize we only replace words
    original = """package main

import "fmt"

func main() {
    fmt.Println("Hello, stuff.")
    fmt.Println("This is a test.")
    fmt.Println("Another line.")
}"""
    
    modified = """package main

import "fmt"

func main() {
    fmt.Println("Hello, blah.")
    fmt.Println("This is a test.")
    fmt.Println("Another line.")
}"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace the word 'stuff' with 'blah'"
    )


def create_empty_file_example_simple(file_path: str) -> Dict:
    """Create example: Create an empty file (no content specified)."""
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**IMPORTANT**: You do NOT directly edit files. You generate tool calls that the system executes.

CRITICAL GUIDELINES:
- Generate tool calls (read_file, write_file) that the system will execute
- You never directly access or modify files - only generate tool calls and content
- Do NOT infer or generate content based on file extensions
- Do NOT create default/example content unless the user explicitly requests it
- If the user says "create a file X" without specifying content, create an EMPTY file
- Do NOT add "test: 1" or any default content to YAML files
- Do NOT add default structure to JSON files
- Only create the exact content the user describes
- If no content is specified, use write_file with empty contents: ""
- Follow the user's instructions precisely"""
    
    user_prompt = f"Create a new file at `{file_path}`"
    
    import uuid
    write_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    # Empty file - no content
    assistant_content = f"""I'll create the new file.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": ""
})}
</tool_call>"""
    
    tool_response_content = "File written successfully."
    
    assistant_content_2 = "Done. The file has been created."
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            },
            {
                "role": "tool",
                "content": tool_response_content,
                "tool_call_id": write_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            }
        ]
    }


def create_append_example(file_path: str) -> Dict:
    """Create example: Append to end."""
    original = """Line 1: First line
Line 2: Second line"""
    
    modified = """Line 1: First line
Line 2: Second line
Line 3: Appended line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Append a new line at the end: 'Line 3: Appended line'"
    )


def create_add_quoted_content_example(file_path: str) -> Dict:
    """Create example: Add content specified in quotes to existing file."""
    original = """existing content
more content"""
    
    modified = """existing content
more content
hey: 1"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add the content 'hey: 1' to the file"
    )


def create_add_quoted_content_to_empty_file_example(file_path: str) -> Dict:
    """Create example: Add content specified in quotes to an EMPTY file."""
    original = ""  # Empty file
    
    modified = """hey: 1"""  # Only the requested content
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add the content 'hey: 1' to the file"
    )


def create_add_quoted_content_to_empty_file_double_quotes_example(file_path: str) -> Dict:
    """Create example: Add content with double quotes to an EMPTY file."""
    original = ""  # Empty file
    
    modified = """test: value"""  # Only the requested content
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        'Add the content "test: value" to the file'
    )


def create_add_double_quoted_content_example(file_path: str) -> Dict:
    """Create example: Add content specified in double quotes."""
    original = """existing content
more content"""
    
    modified = """existing content
more content
test: value"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        'Add the content "test: value" to the file'
    )


def create_replace_quoted_word_example(file_path: str) -> Dict:
    """Create example: Replace word specified in quotes."""
    original = """stuff
more stuff
even more stuff"""
    
    modified = """blah
more blah
even more blah"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace the word 'stuff' with 'blah'"
    )


def create_replace_double_quoted_word_example(file_path: str) -> Dict:
    """Create example: Replace word specified in double quotes."""
    original = """sample text
more sample text"""
    
    modified = """example text
more example text"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        'Replace the word "sample" with "example"'
    )


def create_prepend_example(file_path: str) -> Dict:
    """Create example: Prepend to beginning."""
    original = """Line 1: First line
Line 2: Second line"""
    
    modified = """Line 0: Prepended line
Line 1: First line
Line 2: Second line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a new line at the beginning: 'Line 0: Prepended line'"
    )


def create_multiple_operations_example(file_path: str) -> Dict:
    """Create example: Multiple operations."""
    original = """Header line
Line 1: First line
Line 2: Second line
Line 3: Third line
Footer line"""
    
    modified = """Header line
Line 1: Updated first line
Line 2: Second line
Line 2.5: Inserted line
Line 3: Third line
Footer line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "1. Replace 'First line' with 'Updated first line' in line 1\n2. Insert 'Line 2.5: Inserted line' after line 2"
    )


def create_empty_file_example(file_path: str) -> Dict:
    """Create example: Write to empty file."""
    original = ""
    
    modified = """Line 1: New content
Line 2: More content"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Write the following content to the file:\nLine 1: New content\nLine 2: More content"
    )


def create_new_file_example(file_path: str) -> Dict:
    """Create example: Create a new file from scratch."""
    # For new files, we don't read first - just write
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**IMPORTANT**: You do NOT directly edit files. You generate tool calls that the system executes.

CRITICAL GUIDELINES:
- Generate tool calls (read_file, write_file) that the system will execute
- You never directly access or modify files - only generate tool calls and content
- Do NOT infer or generate content based on file extensions
- Do NOT create default/example content unless the user explicitly requests it
- If the user says "create a file X" without specifying content, create an EMPTY file
- Do NOT add "test: 1" or any default content to YAML files
- Do NOT add default structure to JSON files
- Only create the exact content the user describes
- If no content is specified, use write_file with empty contents: ""
- Follow the user's instructions precisely"""
    
    # For this example, user specifies content, so include it
    file_contents = """package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
"""
    
    user_prompt = f"Create a new file at `{file_path}` with a simple Go program that prints 'Hello, World!'"
    
    import uuid
    write_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    # Embed tool call in assistant content
    assistant_content = f"""I'll create the new file with the requested content.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": file_contents
})}
</tool_call>"""
    
    tool_response_content = "File written successfully."
    
    assistant_content_2 = "Done. The file has been created."
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            },
            {
                "role": "tool",
                "content": tool_response_content,
                "tool_call_id": write_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            }
        ]
    }


def create_new_file_with_content_example(file_path: str) -> Dict:
    """Create example: Create a new file with specific content provided."""
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**IMPORTANT**: You do NOT directly edit files. You generate tool calls that the system executes.

Guidelines:
- Generate tool calls (read_file, write_file) that the system will execute
- You never directly access or modify files - only generate tool calls and content
- Do not infer missing logic
- Do not create domain-specific content
- Only create the content the user describes
- Follow the user's instructions precisely
- If a file doesn't exist, use write_file to create it"""
    
    file_contents = """# My Document

This is a new document.

## Section 1

Content here.

## Section 2

More content.
"""
    
    user_prompt = f"""Create a new file at `{file_path}` with the following content:

# My Document

This is a new document.

## Section 1

Content here.

## Section 2

More content.
"""
    
    import uuid
    write_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    # Embed tool call in assistant content
    assistant_content = f"""I'll create the new file with the specified content.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": file_contents
})}
</tool_call>"""
    
    tool_response_content = "File written successfully."
    
    assistant_content_2 = "Done. The file has been created."
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            },
            {
                "role": "tool",
                "content": tool_response_content,
                "tool_call_id": write_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            }
        ]
    }


def create_new_file_from_template_example(file_path: str) -> Dict:
    """Create example: Create a new file based on a template/description."""
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**IMPORTANT**: You do NOT directly edit files. You generate tool calls that the system executes.

CRITICAL GUIDELINES:
- Generate tool calls (read_file, write_file) that the system will execute
- You never directly access or modify files - only generate tool calls and content
- Do NOT infer or generate content based on file extensions
- Do NOT create default/example content unless the user explicitly requests it
- If the user says "create a file X" without specifying content, create an EMPTY file
- Do NOT add "test: 1" or any default content to YAML files
- Do NOT add default structure to JSON files
- Only create the exact content the user describes
- If no content is specified, use write_file with empty contents: ""
- Follow the user's instructions precisely"""
    
    # Different templates based on file extension (only when user explicitly requests structure)
    if file_path.endswith('.json'):
        file_contents = """{
  "name": "MyApp",
  "version": "1.0.0",
  "description": "A sample application"
}
"""
        user_prompt = f"Create a new JSON file at `{file_path}` with name 'MyApp', version '1.0.0', and description 'A sample application'"
    elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
        file_contents = """app:
  name: MyApp
  version: 1.0.0
  settings:
    debug: false
"""
        user_prompt = f"Create a new YAML file at `{file_path}` with app name 'MyApp', version '1.0.0', and debug set to false"
    elif file_path.endswith('.py'):
        file_contents = """def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
"""
        user_prompt = f"Create a new Python file at `{file_path}` with a main function that prints 'Hello, World!'"
    elif file_path.endswith('.go'):
        file_contents = """package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
"""
        user_prompt = f"Create a new Go file at `{file_path}` with a main function that prints 'Hello, World!'"
    else:
        file_contents = """# New File

This is a new file created from a template.
"""
        user_prompt = f"Create a new file at `{file_path}` with a heading 'New File' and text 'This is a new file created from a template.'"
    
    import uuid
    write_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    assistant_content = f"I'll create the new file with the requested structure."
    
    tool_response_content = "File written successfully."
    
    assistant_content_2 = "Done. The file has been created."
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            },
            {
                "role": "tool",
                "content": tool_response_content,
                "tool_call_id": write_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            }
        ]
    }


def create_whitespace_preservation_example(file_path: str) -> Dict:
    """Create example: Preserve whitespace."""
    original = """    Indented line 1
    Indented line 2
    
    Blank line above
    Indented line 3"""
    
    modified = """    Indented line 1
    Indented line 2
    New indented line
    Blank line above
    Indented line 3"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Insert '    New indented line' after line 2, preserving indentation"
    )


def create_ambiguous_instruction_example(file_path: str) -> Dict:
    """Create example: Handle ambiguous instructions that need resolution."""
    original = """Line 1: First line
Line 2: Second mention here
Line 3: Third line
Line 4: Another Second mention
Line 5: Fifth line"""
    
    modified = """Line 1: First line
Line 2: Second mention here
Line 3: Third line
Line 5: Fifth line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Remove the third line that mentions 'Second'"
    )


def create_noop_example(file_path: str) -> Dict:
    """Create example: No-op request - just read and confirm, don't write."""
    import uuid
    
    content = """Line 1: First line
Line 2: Second line
Line 3: Third line"""
    
    system_prompt = """Your job is to help users modify files by generating tool calls and complete file content.

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

Guidelines:
- Do not infer missing logic
- Do not create domain-specific content
- Only manipulate the text the user describes
- Follow the user's instructions precisely
- Use tools to read, modify, and write files
- If the user asks to confirm or check contents without changes, only read the file"""
    
    user_prompt = f"""Check the contents of `{file_path}` and confirm what's in it. Don't make any changes."""
    
    read_call_id = f"call_{uuid.uuid4().hex[:12]}"
    
    # Embed tool call in assistant content
    assistant_content = f"""I'll read the file to check its contents.

<tool_call>
name: read_file
arguments: {json.dumps({"path": file_path})}
</tool_call>"""
    
    tool_response_content = content
    
    assistant_content_2 = f"""The file `{file_path}` contains:

{content}

No changes were made as requested."""
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            },
            {
                "role": "tool",
                "content": tool_response_content,
                "tool_call_id": read_call_id
            },
            {
                "role": "assistant",
                "content": assistant_content_2
            }
        ]
    }


def create_partial_content_match_example(file_path: str) -> Dict:
    """Create example: Replace based on partial content match."""
    original = """Introduction paragraph
This is a long paragraph starting with 'Foo' that contains
multiple lines of text that need to be replaced.
The paragraph continues here.
End of paragraph
Conclusion paragraph"""
    
    modified = """Introduction paragraph
This is the new paragraph content.
Conclusion paragraph"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace the paragraph starting with 'Foo' with: 'This is the new paragraph content.'"
    )


def create_ambiguous_multiple_matches_example(file_path: str) -> Dict:
    """Create example: Ambiguous instruction with multiple possible matches."""
    original = """Section 1: First section
Line with 'Second' in it
Section 2: Second section
Another line with 'Second' word
Section 3: Third section"""
    
    modified = """Section 1: First section
Line with 'Second' in it
Section 2: Second section
Section 3: Third section"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Remove the line that contains 'Second' and comes after 'Section 2'"
    )


def create_partial_line_match_example(file_path: str) -> Dict:
    """Create example: Match and replace based on partial line content."""
    original = """Config option 1: value1
Config option 2: value2
Config option 3: value3
Other line"""
    
    modified = """Config option 1: value1
Config option 2: new_value
Config option 3: value3
Other line"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Replace the line starting with 'Config option 2' with 'Config option 2: new_value'"
    )


def create_golang_function_edit_example(file_path: str) -> Dict:
    """Create example: Edit Go code - add error handling."""
    original = """package main

import "fmt"

func processData(data string) {
	fmt.Println("Processing:", data)
}

func main() {
	processData("test")
}
"""
    
    modified = """package main

import "fmt"

func processData(data string) error {
	if data == "" {
		return fmt.Errorf("data cannot be empty")
	}
	fmt.Println("Processing:", data)
	return nil
}

func main() {
	if err := processData("test"); err != nil {
		fmt.Println("Error:", err)
	}
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add error handling to the processData function: return an error if data is empty, and update main to handle the error"
    )


def create_golang_struct_edit_example(file_path: str) -> Dict:
    """Create example: Edit Go code - add field to struct."""
    original = """package main

type User struct {
	Name  string
	Email string
}

func (u *User) String() string {
	return fmt.Sprintf("User: %s", u.Name)
}
"""
    
    modified = """package main

type User struct {
	Name  string
	Email string
	Age   int
}

func (u *User) String() string {
	return fmt.Sprintf("User: %s", u.Name)
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add an 'Age' field of type int to the User struct"
    )


def create_python_function_edit_example(file_path: str) -> Dict:
    """Create example: Edit Python code - add parameter and type hints."""
    original = """def calculate_total(items):
    total = 0
    for item in items:
        total += item['price']
    return total
"""
    
    modified = """def calculate_total(items, discount=0.0):
    total = 0
    for item in items:
        total += item['price']
    total = total * (1 - discount)
    return total
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a discount parameter (default 0.0) to calculate_total and apply it to the total before returning"
    )


def create_python_class_edit_example(file_path: str) -> Dict:
    """Create example: Edit Python code - add method to class."""
    original = """class Calculator:
    def __init__(self):
        self.result = 0
    
    def add(self, value):
        self.result += value
        return self.result
"""
    
    modified = """class Calculator:
    def __init__(self):
        self.result = 0
    
    def add(self, value):
        self.result += value
        return self.result
    
    def reset(self):
        self.result = 0
        return self.result
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a reset method to the Calculator class that sets result to 0 and returns it"
    )


def create_rego_rule_edit_example(file_path: str) -> Dict:
    """Create example: Edit Rego code - add condition to deny rule."""
    original = """package example

import rego.v1

deny contains result if {
	some task in input.tasks
	task.status != "Succeeded"
	result := sprintf("Task %s did not succeed", [task.name])
}
"""
    
    modified = """package example

import rego.v1

deny contains result if {
	some task in input.tasks
	task.status != "Succeeded"
	not task.status == "Skipped"
	result := sprintf("Task %s did not succeed", [task.name])
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a condition to exclude skipped tasks from the deny rule: add 'not task.status == \"Skipped\"' before the result assignment"
    )


def create_rego_import_edit_example(file_path: str) -> Dict:
    """Create example: Edit Rego code - add import."""
    original = """package example

import rego.v1

deny contains result if {
	count(input.tasks) == 0
	result := "No tasks found"
}
"""
    
    modified = """package example

import rego.v1

import data.lib

deny contains result if {
	count(input.tasks) == 0
	result := "No tasks found"
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add an import statement for 'data.lib' after the rego.v1 import"
    )


def create_golang_import_edit_example(file_path: str) -> Dict:
    """Create example: Edit Go code - add import."""
    original = """package main

import "fmt"

func main() {
	fmt.Println("Hello")
}
"""
    
    modified = """package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("Hello")
	fmt.Println("Time:", time.Now())
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add the 'time' package to imports and print the current time in main"
    )


def create_python_import_edit_example(file_path: str) -> Dict:
    """Create example: Edit Python code - add import."""
    original = """def get_date():
    return "2024-01-01"
"""
    
    modified = """from datetime import datetime

def get_date():
    return datetime.now().strftime("%Y-%m-%d")
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Import datetime and update get_date to return the current date using datetime.now()"
    )


def create_yaml_config_edit_example(file_path: str) -> Dict:
    """Create example: Edit YAML - modify configuration value."""
    original = """server:
  host: localhost
  port: 8080
  timeout: 30

database:
  name: mydb
  pool_size: 10
"""
    
    modified = """server:
  host: localhost
  port: 8080
  timeout: 60

database:
  name: mydb
  pool_size: 20
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Update server timeout to 60 and database pool_size to 20"
    )


def create_yaml_add_section_example(file_path: str) -> Dict:
    """Create example: Edit YAML - add new section."""
    original = """server:
  host: localhost
  port: 8080

database:
  name: mydb
"""
    
    modified = """server:
  host: localhost
  port: 8080

database:
  name: mydb

logging:
  level: info
  file: app.log
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a new 'logging' section with level 'info' and file 'app.log'"
    )


def create_yaml_nested_edit_example(file_path: str) -> Dict:
    """Create example: Edit YAML - modify nested structure."""
    original = """app:
  features:
    auth: true
    cache: false
  settings:
    debug: true
"""
    
    modified = """app:
  features:
    auth: true
    cache: true
    analytics: true
  settings:
    debug: false
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Set cache to true, add analytics: true under features, and set debug to false"
    )


def create_json_property_edit_example(file_path: str) -> Dict:
    """Create example: Edit JSON - modify property."""
    original = """{
  "name": "MyApp",
  "version": "1.0.0",
  "author": "John Doe",
  "license": "MIT"
}
"""
    
    modified = """{
  "name": "MyApp",
  "version": "2.0.0",
  "author": "John Doe",
  "license": "MIT"
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Update the version field to '2.0.0'"
    )


def create_json_add_field_example(file_path: str) -> Dict:
    """Create example: Edit JSON - add new field."""
    original = """{
  "name": "MyApp",
  "version": "1.0.0",
  "author": "John Doe"
}
"""
    
    modified = """{
  "name": "MyApp",
  "version": "1.0.0",
  "author": "John Doe",
  "description": "A sample application"
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a 'description' field with value 'A sample application'"
    )


def create_json_array_edit_example(file_path: str) -> Dict:
    """Create example: Edit JSON - modify array."""
    original = """{
  "dependencies": [
    "package1",
    "package2"
  ],
  "devDependencies": [
    "dev1"
  ]
}
"""
    
    modified = """{
  "dependencies": [
    "package1",
    "package2",
    "package3"
  ],
  "devDependencies": [
    "dev1",
    "dev2"
  ]
}
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add 'package3' to dependencies array and 'dev2' to devDependencies array"
    )


def create_markdown_heading_edit_example(file_path: str) -> Dict:
    """Create example: Edit Markdown - modify heading."""
    original = """# Introduction

This is the introduction section.

## Getting Started

Follow these steps.
"""
    
    modified = """# Overview

This is the introduction section.

## Getting Started

Follow these steps.
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Change the main heading from 'Introduction' to 'Overview'"
    )


def create_markdown_add_section_example(file_path: str) -> Dict:
    """Create example: Edit Markdown - add new section."""
    original = """# My Document

## Section 1

Content here.

## Section 2

More content.
"""
    
    modified = """# My Document

## Section 1

Content here.

## Section 2

More content.

## Section 3

New section content.
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add a new 'Section 3' with content 'New section content.' after Section 2"
    )


def create_markdown_list_edit_example(file_path: str) -> Dict:
    """Create example: Edit Markdown - modify list."""
    original = """# Features

- Feature 1
- Feature 2

## Requirements

- Requirement A
"""
    
    modified = """# Features

- Feature 1
- Feature 2
- Feature 3

## Requirements

- Requirement A
- Requirement B
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Add 'Feature 3' to the Features list and 'Requirement B' to the Requirements list"
    )


def create_markdown_code_block_edit_example(file_path: str) -> Dict:
    """Create example: Edit Markdown - modify code block."""
    original = """# Example

Here's some code:

```python
def hello():
    print("Hello")
```
"""
    
    modified = """# Example

Here's some code:

```python
def hello(name="World"):
    print(f"Hello, {name}")
```
"""
    
    return create_simple_file_edit_example(
        file_path,
        original,
        modified,
        "Update the code block: add a name parameter with default 'World' and use an f-string in the print statement"
    )


def generate_generic_tool_examples() -> List[Dict]:
    """Generate a variety of generic tool usage examples."""
    examples = []
    
    # Generate multiple examples of each type with different file paths
    file_paths = [
        "example.txt",
        "config.yaml",
        "data.json",
        "script.py",
        "document.md",
        "file.txt",
        "test.txt",
        "sample.txt",
        "output.txt",
        "input.txt"
    ]
    
    example_generators = [
        create_line_replacement_example,
        create_insertion_example,
        create_deletion_example,
        create_text_replacement_example,
        create_simple_word_replacement_example,  # NEW: Emphasizes no content inference
        create_word_replacement_preserve_structure_example,  # NEW: Word replacement in code-like files
        create_replace_quoted_word_example,  # NEW: Replace with single quotes
        create_replace_double_quoted_word_example,  # NEW: Replace with double quotes
        create_append_example,
        create_add_quoted_content_example,  # Add content with single quotes (to existing file)
        create_add_quoted_content_to_empty_file_example,  # NEW: Add content to EMPTY file (single quotes)
        create_add_quoted_content_to_empty_file_double_quotes_example,  # NEW: Add content to EMPTY file (double quotes)
        create_add_double_quoted_content_example,  # Add content with double quotes (to existing file)
        create_prepend_example,
        create_multiple_operations_example,
        create_empty_file_example,
        create_whitespace_preservation_example,
        create_ambiguous_instruction_example,
        create_noop_example,
        create_partial_content_match_example,
        create_ambiguous_multiple_matches_example,
        create_partial_line_match_example,
        # Code editing examples
        create_golang_function_edit_example,
        create_golang_struct_edit_example,
        create_golang_import_edit_example,
        create_python_function_edit_example,
        create_python_class_edit_example,
        create_python_import_edit_example,
        create_rego_rule_edit_example,
        create_rego_import_edit_example,
        # YAML editing examples
        create_yaml_config_edit_example,
        create_yaml_add_section_example,
        create_yaml_nested_edit_example,
        # JSON editing examples
        create_json_property_edit_example,
        create_json_add_field_example,
        create_json_array_edit_example,
        # Markdown editing examples
        create_markdown_heading_edit_example,
        create_markdown_add_section_example,
        create_markdown_list_edit_example,
        create_markdown_code_block_edit_example,
        # File creation examples
        create_new_file_example,
        create_new_file_with_content_example,
        create_new_file_from_template_example,
        create_empty_file_example_simple,  # NEW: Create empty files without inferring content
    ]
    
    # Generate multiple examples of each type with different file paths
    # More examples for foundational skills = better learning
    examples_per_type = 15  # Increased from 5 to 15 for better coverage
    
    # Code-specific file paths
    code_file_paths = {
        'golang': ['main.go', 'handler.go', 'utils.go', 'server.go', 'client.go'],
        'python': ['main.py', 'utils.py', 'handler.py', 'config.py', 'app.py'],
        'rego': ['policy.rego', 'rules.rego', 'validation.rego', 'checks.rego', 'main.rego'],
        'yaml': ['config.yaml', 'docker-compose.yaml', 'k8s.yaml', 'settings.yaml', 'app.yaml'],
        'json': ['package.json', 'config.json', 'data.json', 'settings.json', 'app.json'],
        'markdown': ['README.md', 'docs.md', 'guide.md', 'CHANGELOG.md', 'notes.md'],
    }
    
    for generator in example_generators:
        for i in range(examples_per_type):
            # Use appropriate file paths for code examples
            if 'golang' in generator.__name__:
                file_path = random.choice(code_file_paths['golang'])
            elif 'python' in generator.__name__:
                file_path = random.choice(code_file_paths['python'])
            elif 'rego' in generator.__name__:
                file_path = random.choice(code_file_paths['rego'])
            elif 'yaml' in generator.__name__:
                file_path = random.choice(code_file_paths['yaml'])
            elif 'json' in generator.__name__:
                file_path = random.choice(code_file_paths['json'])
            elif 'markdown' in generator.__name__:
                file_path = random.choice(code_file_paths['markdown'])
            else:
                file_path = random.choice(file_paths)
            examples.append(generator(file_path))
    
    return examples


def main():
    """Generate generic tool usage training data."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate generic tool usage training data")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: data/qwen3-generic-tool-usage-training.jsonl)"
    )
    
    args = parser.parse_args()
    
    # Resolve path relative to project root (rego-training/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    
    if args.output:
        # Use provided output path (resolve relative to current directory or project root)
        output_file = Path(args.output)
        if not output_file.is_absolute():
            # Try relative to current directory first, then project root
            if Path(args.output).exists() or Path.cwd() != project_root:
                output_file = Path(args.output).resolve()
            else:
                output_file = project_root / args.output
    else:
        # Default output file
        output_file = project_root / "data/qwen3-generic-tool-usage-training.jsonl"
    
    # Create data directory if it doesn't exist
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Clear or backup existing file
    if output_file.exists():
        backup = output_file.with_suffix('.jsonl.backup')
        output_file.rename(backup)
        print(f"Backed up existing file to {backup}")
    
    print("Generating generic tool usage training examples...")
    examples = generate_generic_tool_examples()
    
    # Shuffle for better training
    random.seed(42)
    random.shuffle(examples)
    
    # Write to file
    with open(output_file, 'w') as out:
        for example in examples:
            out.write(json.dumps(example) + '\n')
    
    # Calculate number of types from examples (we know examples_per_type = 15)
    examples_per_type = 15
    total_types = len(examples) // examples_per_type
    
    print(f"\n✅ Generated generic tool usage training data:")
    print(f"   Examples created: {len(examples)}")
    print(f"   Examples per type: {examples_per_type}")
    print(f"   Total types: {total_types}")
    print(f"   Output: {output_file}")
    print(f"\n   Example types:")
    print(f"   Basic operations:")
    print(f"   - Line replacement")
    print(f"   - Insertion")
    print(f"   - Deletion")
    print(f"   - Text replacement")
    print(f"   - Append")
    print(f"   - Prepend")
    print(f"   - Multiple operations")
    print(f"   - Empty file handling")
    print(f"   - Whitespace preservation")
    print(f"   Advanced scenarios:")
    print(f"   - Ambiguous instruction resolution")
    print(f"   - No-op requests (read-only)")
    print(f"   - Partial content matching")
    print(f"   - Ambiguous multiple matches")
    print(f"   - Partial line matching")
    print(f"   Code editing:")
    print(f"   - Go: function edits, struct edits, imports")
    print(f"   - Python: function edits, class edits, imports")
    print(f"   - Rego: rule edits, import edits")
    print(f"   - YAML: config edits, add sections, nested edits")
    print(f"   - JSON: property edits, add fields, array edits")
    print(f"   - Markdown: heading edits, add sections, list edits, code blocks")
    print(f"   File creation:")
    print(f"   - Create new files from scratch")
    print(f"   - Create files with provided content")
    print(f"   - Create files from templates/descriptions")
    print(f"\n   💡 Tip: For foundational skills like tool usage, more examples")
    print(f"      help ensure robust learning. Consider 400-600+ examples")
    print(f"      for production use.")


if __name__ == "__main__":
    main()
