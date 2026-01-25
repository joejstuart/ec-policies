#!/usr/bin/env python3
"""
Remove empty line between METADATA block and deny rule.
"""

import re
from pathlib import Path

def fix_file(filepath: Path):
    """Fix a single Rego file."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Find where METADATA ends and deny/allow starts
    metadata_end = None
    deny_start = None
    
    for i, line in enumerate(lines):
        if '# METADATA' in line:
            # Find end of metadata block (line ending with #)
            for j in range(i, len(lines)):
                if lines[j].strip() == '#' or (lines[j].strip().startswith('#') and 'short_name' in lines[j-1] if j > 0 else False):
                    # Check if next non-empty line is deny/allow
                    for k in range(j + 1, len(lines)):
                        if lines[k].strip():
                            if lines[k].strip().startswith('deny ') or lines[k].strip().startswith('allow '):
                                metadata_end = j
                                deny_start = k
                                break
                            break
                    if deny_start:
                        break
                if deny_start:
                    break
            break
    
    if metadata_end is not None and deny_start is not None:
        # Remove blank lines between metadata and deny
        new_lines = lines[:metadata_end + 1]  # Include the # line
        # Skip blank lines
        for i in range(metadata_end + 1, deny_start):
            if lines[i].strip() != '':
                new_lines.append(lines[i])
        # Add deny/allow and rest
        new_lines.extend(lines[deny_start:])
        
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
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
