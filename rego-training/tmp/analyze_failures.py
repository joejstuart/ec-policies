#!/usr/bin/env python3
"""
Analyze validation failures to identify patterns that need fixing.
"""

import json
import re
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from validate_and_add_training import load_test_case_definitions, find_matching_test_case, validate_with_test_definitions
from validate_rego_training import RegoValidator, TestCase

def extract_rego_code(rego_content: str) -> str:
    """Extract just the deny rule code from Rego file."""
    lines = rego_content.split('\n')
    start_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith('deny '):
            start_idx = i
            break
    if start_idx is None:
        return ""
    return '\n'.join(lines[start_idx:]).strip()

def analyze_failures():
    """Analyze validation failures and categorize them."""
    test_defs = load_test_case_definitions()
    rego_dir = Path("rego_rules")
    validator = RegoValidator()
    
    failures_by_pattern = {}
    total_failures = 0
    
    rego_files = sorted(rego_dir.glob("*.rego"))
    
    for rego_file in rego_files:
        try:
            with open(rego_file) as f:
                content = f.read()
            
            title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', content)
            if not title_match:
                continue
            
            nl = title_match.group(1).strip()
            rego_code = extract_rego_code(content)
            
            if not rego_code:
                continue
            
            result = validate_with_test_definitions(nl, rego_code, test_defs)
            
            if not result.passed:
                total_failures += 1
                
                # Categorize by pattern
                pattern = "unknown"
                if "annotation" in nl.lower():
                    pattern = "annotation"
                elif "label" in nl.lower():
                    pattern = "label"
                elif "bundle" in nl.lower():
                    pattern = "bundle"
                elif "timestamp" in nl.lower() or "rfc3339" in nl.lower():
                    pattern = "timestamp"
                elif "result" in nl.lower():
                    pattern = "result"
                elif "parameter" in nl.lower():
                    pattern = "parameter"
                elif "status" in nl.lower():
                    pattern = "status"
                elif "metadata" in nl.lower():
                    pattern = "metadata"
                elif "subject" in nl.lower():
                    pattern = "subject"
                elif "material" in nl.lower():
                    pattern = "material"
                elif "all tasks" in nl.lower():
                    pattern = "compound_all_tasks"
                
                if pattern not in failures_by_pattern:
                    failures_by_pattern[pattern] = []
                
                failures_by_pattern[pattern].append({
                    "file": rego_file.name,
                    "nl": nl[:60] + "...",
                    "errors": result.errors[:2]
                })
        except Exception as e:
            print(f"Error processing {rego_file.name}: {e}")
    
    print(f"Total failures: {total_failures}\n")
    print("Failures by pattern:")
    for pattern, failures in sorted(failures_by_pattern.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n{pattern}: {len(failures)} failures")
        for f in failures[:3]:
            print(f"  - {f['file']}: {f['errors'][0] if f['errors'] else 'Unknown error'}")

if __name__ == "__main__":
    analyze_failures()
