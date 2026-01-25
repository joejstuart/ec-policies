#!/usr/bin/env python3
"""
Fix annotation and label rules to handle empty annotations/labels correctly.

The test cases expect that empty annotations/labels should pass (not deny),
so we need to add a check that annotations/labels exist and are not empty
before checking for specific keys.
"""

import re
from pathlib import Path

def fix_annotation_rule(content: str) -> str:
    """Fix annotation checking rules."""
    # Pattern: annotations := ... \n not annotations["key"]
    # Fix: Add check that annotations exist and count > 0
    pattern = r'(annotations\s*:=\s*task\.invocation\.environment\.annotations)\s*\n(\s*)(not\s+annotations\["([^"]+)"\])'
    
    def replacement(match):
        indent = match.group(2)
        var_name = "annotations"
        key = match.group(4)
        return f'{match.group(1)}\n{indent}{var_name}\n{indent}count({var_name}) > 0\n{indent}{match.group(3)}'
    
    return re.sub(pattern, replacement, content)

def fix_label_rule(content: str) -> str:
    """Fix label checking rules."""
    pattern = r'(labels\s*:=\s*task\.invocation\.environment\.labels)\s*\n(\s*)(not\s+labels\["([^"]+)"\])'
    
    def replacement(match):
        indent = match.group(2)
        var_name = "labels"
        return f'{match.group(1)}\n{indent}{var_name}\n{indent}count({var_name}) > 0\n{indent}{match.group(3)}'
    
    return re.sub(pattern, replacement, content)

def main():
    """Fix all annotation and label rules."""
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
            
            # Fix annotation rules
            if "annotation" in content.lower() and "annotations[" in content:
                content = fix_annotation_rule(content)
            
            # Fix label rules
            if "label" in content.lower() and "labels[" in content and "label" not in rego_file.stem.lower():
                # Avoid double-fixing label rules that are actually about annotations
                if "annotations[" not in content or "label" in rego_file.stem.lower():
                    content = fix_label_rule(content)
            
            if content != original:
                with open(rego_file, 'w') as f:
                    f.write(content)
                
                # Format with opa fmt
                import subprocess
                subprocess.run(["opa", "fmt", "-w", str(rego_file)], 
                             capture_output=True, check=False)
                
                fixed_count += 1
                if fixed_count % 10 == 0:
                    print(f"  Fixed {fixed_count} files...")
        except Exception as e:
            print(f"  Error processing {rego_file.name}: {e}")
    
    print(f"\n✅ Fixed {fixed_count} annotation/label rules")

if __name__ == "__main__":
    main()
