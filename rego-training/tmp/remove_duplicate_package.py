#!/usr/bin/env python3
"""
Remove duplicate package declarations from Rego files.
"""

from pathlib import Path

def fix_file(filepath: Path):
    """Fix a single Rego file."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    package_count = 0
    new_lines = []
    skip_next_empty = False
    
    for i, line in enumerate(lines):
        if line.strip().startswith('package '):
            package_count += 1
            if package_count == 1:
                # Keep first package
                new_lines.append(line)
                # Check if next line is empty
                if i + 1 < len(lines) and lines[i + 1].strip() == '':
                    skip_next_empty = True
            else:
                # Skip duplicate package
                continue
        elif skip_next_empty and line.strip() == '':
            # Skip empty line after first package
            skip_next_empty = False
            continue
        else:
            new_lines.append(line)
    
    if package_count > 1:
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
