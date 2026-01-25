#!/usr/bin/env python3
"""Fix remaining duplicate deny rules by finding and removing exact duplicates."""

import re
from pathlib import Path

def fix_duplicates(file_path):
    """Remove duplicate deny rules from a rego file."""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    content = ''.join(lines)
    
    # Find all deny rule blocks - look for "deny contains result if {" to matching "}"
    deny_blocks = []
    i = 0
    while i < len(content):
        if content[i:].startswith('deny contains result if {'):
            # Find the matching closing brace
            start = i
            brace_count = 0
            j = i
            while j < len(content):
                if content[j] == '{':
                    brace_count += 1
                elif content[j] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = j + 1
                        deny_blocks.append((start, end, content[start:end]))
                        i = end
                        break
                j += 1
            else:
                i += 1
        else:
            i += 1
    
    if len(deny_blocks) <= 1:
        return False  # No duplicates
    
    # Check if all blocks are identical
    first_block = deny_blocks[0][2]
    all_same = all(block[2] == first_block for block in deny_blocks[1:])
    
    if all_same:
        # Remove all but the first
        new_content = content
        for start, end in reversed(deny_blocks[1:]):
            # Remove trailing whitespace/newlines too
            while end < len(new_content) and new_content[end] in ' \t\n':
                end += 1
            new_content = new_content[:start] + new_content[end:]
        
        with open(file_path, 'w') as f:
            f.write(new_content)
        return True
    
    return False

def main():
    rego_dir = Path(__file__).parent.parent / 'rego_rules'
    
    fixed = []
    for rego_file in sorted(rego_dir.glob('*.rego')):
        if fix_duplicates(rego_file):
            fixed.append(rego_file.name)
    
    if fixed:
        print(f"Fixed duplicates in {len(fixed)} files:")
        for f in fixed:
            print(f"  - {f}")
    else:
        print("No duplicate deny rules found")

if __name__ == '__main__':
    main()
