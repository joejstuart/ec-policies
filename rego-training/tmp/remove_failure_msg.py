#!/usr/bin/env python3
"""
Remove failure_msg metadata from all Rego files in rego_rules/ directory.
"""

import re
from pathlib import Path

def remove_failure_msg(content: str) -> str:
    """Remove failure_msg line from METADATA block."""
    # Pattern to match failure_msg line (with or without indentation)
    pattern = r'^\s*#\s*failure_msg:.*$'
    
    # Remove the line
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        if re.match(pattern, line):
            continue  # Skip this line
        new_lines.append(line)
    
    return '\n'.join(new_lines)

def main():
    """Process all Rego files."""
    rego_dir = Path("rego_rules")
    
    if not rego_dir.exists():
        print(f"Directory {rego_dir} does not exist")
        return
    
    rego_files = list(rego_dir.glob("*.rego"))
    print(f"Processing {len(rego_files)} Rego files...")
    
    updated = 0
    for rego_file in rego_files:
        try:
            with open(rego_file, 'r') as f:
                content = f.read()
            
            # Check if failure_msg exists
            if 'failure_msg:' in content:
                new_content = remove_failure_msg(content)
                
                with open(rego_file, 'w') as f:
                    f.write(new_content)
                
                updated += 1
        except Exception as e:
            print(f"Error processing {rego_file}: {e}")
    
    print(f"Updated {updated} files")

if __name__ == "__main__":
    main()
