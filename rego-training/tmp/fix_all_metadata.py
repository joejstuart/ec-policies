#!/usr/bin/env python3
"""
Fix METADATA block position in all Rego files - move metadata before package.
"""

import re
from pathlib import Path

def fix_file(filepath: Path):
    """Fix a single Rego file."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Find positions
    package_idx = None
    metadata_start = None
    metadata_end = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('package '):
            package_idx = i
        elif '# METADATA' in line:
            metadata_start = i
    
    # If metadata is already before package, skip
    if metadata_start is not None and package_idx is not None and metadata_start < package_idx:
        return False
    
    # If metadata is after package, need to move it
    if metadata_start is not None and package_idx is not None and metadata_start > package_idx:
        # Find end of metadata block
        for i in range(metadata_start + 1, len(lines)):
            if lines[i].strip() == '':
                # Check if next non-empty line is not a comment
                for j in range(i + 1, len(lines)):
                    if lines[j].strip():
                        if not lines[j].strip().startswith('#'):
                            metadata_end = i + 1
                            break
                        break
                if metadata_end:
                    break
            elif lines[i].strip().startswith('deny ') or lines[i].strip().startswith('allow '):
                metadata_end = i
                break
        
        if metadata_end is None:
            metadata_end = len(lines)
        
        # Extract metadata block
        metadata_block = lines[metadata_start:metadata_end]
        
        # Remove metadata from current position
        new_lines = lines[:metadata_start] + lines[metadata_end:]
        
        # Find new package position
        new_package_idx = None
        for i, line in enumerate(new_lines):
            if line.strip().startswith('package '):
                new_package_idx = i
                break
        
        if new_package_idx is not None:
            # Ensure metadata ends with blank line
            if metadata_block and metadata_block[-1].strip() != '':
                metadata_block.append('\n')
            
            # Insert metadata before package
            result = metadata_block + new_lines[new_package_idx:]
            
            with open(filepath, 'w') as f:
                f.writelines(result)
            
            return True
    
    return False

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
            if fix_file(rego_file):
                updated += 1
        except Exception as e:
            print(f"Error processing {rego_file}: {e}")
    
    print(f"Updated {updated} files")

if __name__ == "__main__":
    main()
