#!/usr/bin/env python3
"""
Generate SBOM training data from all Rego rules in sbom_rego_rules/ directory.

This script:
1. Reads each Rego file from sbom_rego_rules/
2. Extracts natural language from METADATA
3. Extracts Rego code
4. Validates against sbom_data/test_case_definitions.json
5. Generates training data in JSONL format for SBOM policies
"""

import json
import re
import sys
from pathlib import Path

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(parent_dir))
# Import from obsolete directory
import importlib.util
spec = importlib.util.spec_from_file_location(
    "validate_and_add_training",
    parent_dir / "scripts" / "obsolete" / "validate_and_add_training.py"
)
validate_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_module)
load_test_case_definitions = validate_module.load_test_case_definitions
find_matching_test_case = validate_module.find_matching_test_case
validate_with_test_definitions = validate_module.validate_with_test_definitions

def extract_metadata(rego_content: str) -> dict:
    """Extract METADATA from Rego file."""
    metadata = {}
    
    # Extract title
    title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', rego_content)
    if title_match:
        metadata['title'] = title_match.group(1).strip()
    
    # Extract description
    desc_match = re.search(r'#\s*description:\s*>-?\s*\n((?:\s*#.*\n)*)', rego_content)
    if desc_match:
        desc_lines = desc_match.group(1)
        # Remove # and leading spaces from each line
        desc = '\n'.join([line.lstrip('#').strip() for line in desc_lines.split('\n') if line.strip()])
        metadata['description'] = desc
    
    return metadata

def extract_rego_code(rego_content: str) -> str:
    """Extract just the deny rule code from Rego file."""
    # Remove package and import lines, keep everything from first deny onwards
    lines = rego_content.split('\n')
    start_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('deny '):
            start_idx = i
            break
    
    if start_idx is None:
        return ""
    
    # Get everything from first deny to end of file
    rego_code = '\n'.join(lines[start_idx:]).strip()
    return rego_code

def create_assistant_content(rego_code: str, natural_language: str) -> str:
    """Create assistant content with Rego code and explanation."""
    # Extract key steps from the natural language
    explanation = f"```rego\n{rego_code}\n```\n\n"
    explanation += "This rule validates the requirement by checking the SBOM structure."
    
    return explanation

def generate_training_example(natural_language: str, rego_code: str) -> dict:
    """Create a training example in JSONL format for SBOM policies."""
    system_prompt = """You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of SBOM (Software Bill of Materials) attestations and can translate natural language policy requirements into Rego code.

**IMPORTANT**: Use pure Rego without importing any libraries from this repo. Access SBOMs directly from attestations.

## SBOM Access Pattern

SBOMs are accessed directly from `input.attestations` by checking the `predicateType`:

**For SPDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://spdx.dev/Document"
sbom := statement.predicate
```

**For CycloneDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://cyclonedx.org/bom"
sbom := statement.predicate
```

## SPDX SBOM Structure

After accessing the SBOM via `sbom := statement.predicate`:
- `sbom.packages` - Array of packages in the SPDX SBOM
- `sbom.files` - Array of files in the SPDX SBOM
- `sbom.name` - SBOM document name (usually image reference)
- `sbom.creationInfo` - Creation metadata
- `sbom.SPDXID` - Document identifier (typically "SPDXRef-DOCUMENT")
- `sbom.spdxVersion` - SPDX specification version (e.g., "SPDX-2.3")

## SPDX Package Structure

- `pkg.name` - Package name
- `pkg.versionInfo` - Package version
- `pkg.supplier` - Package supplier (e.g., "Organization: Red Hat, Inc.")
- `pkg.licenseDeclared` - Declared license
- `pkg.externalRefs` - Array of external references (PURL, CPE, etc.)
- `ref.referenceType` - Reference type (e.g., "purl", "cpe23Type")
- `ref.referenceLocator` - Reference value (PURL string, CPE string, etc.)
- `ref.referenceCategory` - Reference category (e.g., "PACKAGE_MANAGER", "SECURITY")

## CycloneDX SBOM Structure

After accessing the SBOM via `sbom := statement.predicate`:
- `sbom.components` - Array of components in the CycloneDX SBOM
- `sbom.bomFormat` - Format identifier (e.g., "CycloneDX")
- `sbom.specVersion` - CycloneDX specification version
- `comp.type` - Component type (e.g., "library", "application")
- `comp.name` - Component name
- `comp.version` - Component version
- `comp.purl` - Package URL for the component

## Common Patterns

- Access SPDX SBOM: `some att in input.attestations; statement := att.statement; statement.predicateType == "https://spdx.dev/Document"; sbom := statement.predicate`
- Access CycloneDX SBOM: `some att in input.attestations; statement := att.statement; statement.predicateType == "https://cyclonedx.org/bom"; sbom := statement.predicate`
- Iterate packages: `some pkg in sbom.packages`
- Iterate external references: `some ref in pkg.externalRefs`
- Check PURL: `ref.referenceType == "purl"`
- Check CPE: `ref.referenceType == "cpe23Type"`
- Check package count: `count(sbom.packages) == 0`

## Important Rules

1. **No Library Imports**: Do NOT import `data.lib.sbom` or any other libraries from this repo
2. **Direct Access**: Always access SBOMs directly from `input.attestations` using the pattern above
3. **Pure Rego**: Use only standard Rego language features

Write Rego deny rules that check the SBOM structure using pure Rego."""
    
    assistant_content = create_assistant_content(rego_code, natural_language)
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": natural_language
            },
            {
                "role": "assistant",
                "content": assistant_content
            }
        ]
    }

def main():
    """Generate SBOM training data from all Rego rules."""
    rego_dir = Path("../sbom_rego_rules")
    output_file = Path("../sbom_data/qwen3-sbom-training-data.jsonl")
    test_definitions_file = Path("../sbom_data/test_case_definitions.json")
    
    if not rego_dir.exists():
        print(f"Error: {rego_dir} does not exist")
        return
    
    # Create data directory if it doesn't exist
    output_file.parent.mkdir(exist_ok=True)
    
    # Load test definitions if they exist
    test_definitions = None
    if test_definitions_file.exists():
        try:
            test_definitions = load_test_case_definitions(str(test_definitions_file))
        except Exception as e:
            print(f"Warning: Could not load test definitions: {e}")
    
    # Clear or backup existing file
    if output_file.exists():
        backup = output_file.with_suffix('.jsonl.backup')
        output_file.rename(backup)
        print(f"Backed up existing file to {backup}")
    
    rego_files = sorted(rego_dir.glob("*.rego"))
    print(f"Processing {len(rego_files)} SBOM Rego files...")
    
    validated_count = 0
    failed_count = 0
    skipped_count = 0
    
    with open(output_file, 'w') as out:
        for rego_file in rego_files:
            try:
                with open(rego_file) as f:
                    rego_content = f.read()
                
                # Extract metadata
                metadata = extract_metadata(rego_content)
                natural_language = metadata.get('title', '')
                
                if not natural_language:
                    print(f"  ⚠️  Skipping {rego_file.name}: No title found")
                    skipped_count += 1
                    continue
                
                # Extract Rego code
                rego_code = extract_rego_code(rego_content)
                if not rego_code:
                    print(f"  ⚠️  Skipping {rego_file.name}: No deny rule found")
                    skipped_count += 1
                    continue
                
                # Validate
                if test_definitions:
                    result = validate_with_test_definitions(natural_language, rego_code, test_definitions)
                else:
                    print(f"  ⚠️  No test definitions found, skipping validation for {rego_file.name}")
                    result = None
                
                if result and not result.passed:
                    print(f"  ❌ Failed validation: {rego_file.name}")
                    for error in result.errors:
                        print(f"     - {error}")
                    failed_count += 1
                    continue
                
                # Generate training example
                example = generate_training_example(natural_language, rego_code)
                
                # Write to JSONL file
                out.write(json.dumps(example) + '\n')
                validated_count += 1
                
                if validated_count % 50 == 0:
                    print(f"  Processed {validated_count} files...")
                    
            except Exception as e:
                print(f"  ❌ Error processing {rego_file.name}: {e}")
                failed_count += 1
    
    print(f"\n✅ Generated SBOM training data:")
    print(f"   Validated and added: {validated_count}")
    print(f"   Failed validation: {failed_count}")
    print(f"   Skipped: {skipped_count}")
    print(f"   Output: {output_file}")

if __name__ == "__main__":
    main()
