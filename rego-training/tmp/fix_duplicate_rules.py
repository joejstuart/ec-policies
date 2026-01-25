#!/usr/bin/env python3
"""
Remove duplicate deny rules from Rego files.
"""

from pathlib import Path
import re

def fix_duplicate_rules(content: str) -> str:
    """Remove duplicate deny rules."""
    lines = content.split('\n')
    
    # Find all deny rule starts
    deny_starts = []
    for i, line in enumerate(lines):
        if line.strip().startswith('deny contains result if'):
            deny_starts.append(i)
    
    if len(deny_starts) <= 1:
        return content  # No duplicates
    
    # Keep only the first deny rule
    # Find where the first deny rule ends
    first_start = deny_starts[0]
    first_end = len(lines)
    
    # Find the closing brace of the first deny rule
    brace_count = 0
    for i in range(first_start, len(lines)):
        line = lines[i]
        brace_count += line.count('{')
        brace_count -= line.count('}')
        if brace_count == 0 and i > first_start:
            first_end = i + 1
            break
    
    # Remove everything from second deny onwards
    new_lines = lines[:first_end]
    
    # Remove any trailing empty deny blocks
    while new_lines and (not new_lines[-1].strip() or new_lines[-1].strip() == '}'):
        if new_lines[-1].strip() == '}':
            new_lines.pop()
        else:
            break
    
    return '\n'.join(new_lines)

def main():
    """Fix all files with duplicate deny rules."""
    rego_dir = Path("rego_rules")
    
    if not rego_dir.exists():
        print(f"Error: {rego_dir} does not exist")
        return
    
    rego_files = sorted(rego_dir.glob("*.rego"))
    print(f"Processing {len(rego_files)} Rego files...")
    
    fixed_count = 0
    
    for rego_file in rego_files:
        try:
            with open(rego_file) as f:
                content = f.read()
            
            original = content
            content = fix_duplicate_rules(content)
            
            if content != original:
                with open(rego_file, 'w') as f:
                    f.write(content)
                
                # Format with opa fmt
                import subprocess
                subprocess.run(["opa", "fmt", "-w", str(rego_file)], 
                             capture_output=True, check=False)
                
                fixed_count += 1
        except Exception as e:
            print(f"  Error processing {rego_file.name}: {e}")
    
    print(f"\n✅ Fixed {fixed_count} files with duplicate rules")

if __name__ == "__main__":
    main()
