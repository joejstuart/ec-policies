#!/usr/bin/env python3
"""Fix common syntax errors in rego files."""

import re
import subprocess
from pathlib import Path

def fix_file(file_path):
    """Fix syntax errors in a rego file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    original = content
    
    # Fix: Remove trailing closing braces that shouldn't be there
    # Pattern: } followed by whitespace and another }
    content = re.sub(r'\}\s*\n\s*\}', '}', content)
    
    # Fix: Remove duplicate package declarations
    packages = list(re.finditer(r'^package\s+\w+', content, re.MULTILINE))
    if len(packages) > 1:
        # Keep first, remove rest
        for match in reversed(packages[1:]):
            start = match.start()
            end = match.end()
            # Remove the line
            while start > 0 and content[start-1] != '\n':
                start -= 1
            while end < len(content) and content[end] != '\n':
                end += 1
            if end < len(content):
                end += 1  # Include the newline
            content = content[:start] + content[end:]
    
    # Fix: Remove empty deny blocks
    content = re.sub(r'deny contains result if \{\s*\}', '', content)
    
    if content != original:
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    rego_dir = Path(__file__).parent.parent / 'rego_rules'
    
    fixed_count = 0
    for rego_file in rego_dir.glob('*.rego'):
        if fix_file(rego_file):
            fixed_count += 1
            print(f"Fixed syntax in {rego_file.name}")
    
    # Now format all files
    print("\nFormatting all rego files...")
    result = subprocess.run(['opa', 'fmt', '-w'] + list(map(str, rego_dir.glob('*.rego'))), 
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Format errors: {result.stderr}")
    else:
        print("All files formatted successfully")
    
    print(f"\nFixed {fixed_count} files")

if __name__ == '__main__':
    main()
