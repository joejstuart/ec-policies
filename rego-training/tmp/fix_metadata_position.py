#!/usr/bin/env python3
"""
Fix METADATA block position in all Rego files.

METADATA should be above the package declaration, not after it.
"""

import re
from pathlib import Path

def fix_metadata_position(content: str) -> str:
    """Move METADATA block above package declaration."""
    lines = content.split('\n')
    
    # Find positions
    package_line = None
    metadata_start = None
    metadata_end = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('package '):
            package_line = i
        elif '# METADATA' in line:
            metadata_start = i
    
    # If no metadata or no package, return as-is
    if metadata_start is None or package_line is None:
        return content
    
    # If metadata is already before package, return as-is
    if metadata_start < package_line:
        return content
    
    # Metadata is after package - need to move it
    # Find end of metadata block
    for i in range(metadata_start + 1, len(lines)):
        line = lines[i]
        # End of metadata is empty line followed by non-comment, or deny/allow rule
        if line.strip() == '':
            # Check next non-empty line
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    if not lines[j].strip().startswith('#'):
                        metadata_end = i + 1
                        break
                    break
            if metadata_end:
                break
        elif line.strip().startswith('deny ') or line.strip().startswith('allow '):
            metadata_end = i
            break
    
    if metadata_end is None:
        metadata_end = len(lines)
    
    # Extract metadata block
    # Check if there's a comment line before METADATA
    if metadata_start > 0 and lines[metadata_start - 1].strip() == '#':
        metadata_start -= 1
    
    metadata_block = lines[metadata_start:metadata_end]
    
    # Remove metadata from current position
    new_lines = lines[:metadata_start] + lines[metadata_end:]
    
    # Find new package position after removal
    new_package_line = None
    for i, line in enumerate(new_lines):
        if line.strip().startswith('package '):
            new_package_line = i
            break
    
    if new_package_line is None:
        return content
    
    # Ensure metadata block ends with blank line
    if metadata_block and metadata_block[-1].strip() != '':
        metadata_block.append('')
    
    # Insert metadata before package
    result = metadata_block + new_lines[new_package_line:]
    return '\n'.join(result)

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
            
            new_content = fix_metadata_position(content)
            
            if new_content != content:
                with open(rego_file, 'w') as f:
                    f.write(new_content)
                
                updated += 1
        except Exception as e:
            print(f"Error processing {rego_file}: {e}")
    
    print(f"Updated {updated} files")

if __name__ == "__main__":
    main()
