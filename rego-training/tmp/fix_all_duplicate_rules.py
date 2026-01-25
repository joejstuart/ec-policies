#!/usr/bin/env python3
"""Fix all duplicate deny rules in rego files."""

import re
import os
from pathlib import Path

def fix_duplicate_deny_rules(file_path):
    """Remove duplicate deny rules from a rego file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Find all deny rule blocks
    # Pattern: deny contains result if { ... }
    deny_pattern = r'(deny contains result if \{[^}]*\})'
    
    matches = list(re.finditer(deny_pattern, content, re.DOTALL))
    
    if len(matches) <= 1:
        return False  # No duplicates
    
    # Get all deny rule blocks
    deny_blocks = [m.group(1) for m in matches]
    
    # Keep only the first one (they should be identical)
    if len(set(deny_blocks)) == 1:
        # All duplicates are identical, keep first
        first_block = deny_blocks[0]
        
        # Replace all occurrences with just one
        new_content = content
        for i, match in enumerate(matches):
            if i == 0:
                continue  # Keep first
            # Remove this duplicate
            start = match.start()
            end = match.end()
            # Also remove any trailing whitespace/newlines
            while end < len(new_content) and new_content[end] in ' \t\n':
                end += 1
            new_content = new_content[:start] + new_content[end:]
        
        # Also remove any extra closing braces that might be left
        new_content = re.sub(r'\}\s*\n\s*\}', '}', new_content)
        
        with open(file_path, 'w') as f:
            f.write(new_content)
        
        return True
    
    return False

def main():
    rego_dir = Path(__file__).parent.parent / 'rego_rules'
    
    fixed_count = 0
    for rego_file in rego_dir.glob('*.rego'):
        if fix_duplicate_deny_rules(rego_file):
            fixed_count += 1
            print(f"Fixed duplicates in {rego_file.name}")
    
    print(f"\nFixed {fixed_count} files with duplicate deny rules")

if __name__ == '__main__':
    main()
