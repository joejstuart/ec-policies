#!/usr/bin/env python3
"""
Fix METADATA block position in all Rego files.

Order should be:
1. package
2. imports
3. METADATA
4. rule
"""

import re
from pathlib import Path

def fix_file(filepath: Path):
    """Fix a single Rego file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    
    # Find positions
    package_line = None
    import_lines = []
    metadata_start = None
    metadata_end = None
    deny_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('package '):
            if package_line is None:
                package_line = line
        elif line.strip().startswith('import '):
            import_lines.append(line)
        elif '# METADATA' in line:
            if metadata_start is None:
                metadata_start = i
        elif line.strip().startswith('deny ') or line.strip().startswith('allow '):
            if deny_idx is None:
                deny_idx = i
                break
    
    # If we don't have all required parts, skip
    if package_line is None or not import_lines or metadata_start is None or deny_idx is None:
        return False
    
    # Find end of metadata block
    metadata_end = None
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
    
    # Get rule and everything after
    rule_lines = lines[deny_idx:]
    
    # Check if already in correct order
    # Find current positions
    current_package_idx = None
    current_import_idx = None
    current_metadata_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('package '):
            current_package_idx = i
        elif line.strip().startswith('import ') and current_import_idx is None:
            current_import_idx = i
        elif '# METADATA' in line and current_metadata_idx is None:
            current_metadata_idx = i
            break
    
    # Check if order is correct
    if (current_package_idx is not None and current_import_idx is not None and 
        current_metadata_idx is not None and current_package_idx < current_import_idx < current_metadata_idx < deny_idx):
        return False
    
    # Build new content in correct order
    result = []
    
    # 1. Package
    result.append(package_line)
    result.append('')
    
    # 2. Imports
    result.extend(import_lines)
    result.append('')
    
    # 3. Metadata
    result.extend(metadata_block)
    if metadata_block and metadata_block[-1].strip() != '':
        result.append('')
    
    # 4. Rule
    result.extend(rule_lines)
    
    new_content = '\n'.join(result)
    
    # Only update if different
    if new_content != content:
        with open(filepath, 'w') as f:
            f.write(new_content)
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
