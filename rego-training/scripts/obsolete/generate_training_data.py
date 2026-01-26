#!/usr/bin/env python3
"""
Automated training data generation with validation.

This script generates training examples by:
1. Using attestation structure documentation as reference
2. Generating or accepting Rego code candidates
3. Validating against test cases
4. Adding to training data if validation passes
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Import validation modules
try:
    from validate_rego_training import validate_training_example, ValidationResult
    from validate_and_add_training import add_to_training_data, load_test_case_definitions
except ImportError:
    # Handle relative imports
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from validate_rego_training import validate_training_example, ValidationResult
    from validate_and_add_training import add_to_training_data, load_test_case_definitions


@dataclass
class TrainingExample:
    """A training example with all components."""
    natural_language: str
    rego_code: str
    explanation: str
    system_prompt: str


class DocContentExtractor:
    """Extract content from attestation structure documentation."""
    
    def __init__(self, doc_path: str = "docs/attestation-structure-training-data.md"):
        self.doc_path = Path(doc_path)
        self.content = self._load_doc()
    
    def _load_doc(self) -> str:
        """Load documentation content."""
        if not self.doc_path.exists():
            return ""
        return self.doc_path.read_text()
    
    def extract_section(self, section_title: str) -> str:
        """Extract a section from the documentation."""
        # Find section by title
        pattern = rf"##+ {re.escape(section_title)}(.*?)(?=##+ |$)"
        match = re.search(pattern, self.content, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""
    
    def extract_path_mappings(self) -> Dict[str, str]:
        """Extract natural language to path mappings from tables."""
        mappings = {}
        
        # Find all tables with path mappings
        table_pattern = r"\| \"([^\"]+)\" \| `([^`]+)` \|"
        matches = re.findall(table_pattern, self.content)
        
        for natural_lang, path in matches:
            mappings[natural_lang.lower()] = path
        
        return mappings
    
    def extract_common_patterns(self) -> List[str]:
        """Extract common patterns section."""
        patterns_section = self.extract_section("Common Patterns")
        if not patterns_section:
            return []
        
        # Extract code blocks
        code_pattern = r"```rego\n(.*?)\n```"
        patterns = re.findall(code_pattern, patterns_section, re.DOTALL)
        return patterns
    
    def generate_system_prompt(self) -> str:
        """Generate system prompt from documentation."""
        # Extract key sections
        structure_overview = self.extract_section("Input Structure Overview")
        path_mappings = self.extract_section("Key Path Mappings")
        common_patterns = self.extract_section("Common Patterns")
        
        system_prompt = f"""You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.

## Attestation Structure

{structure_overview[:500]}...

## Key Path Mappings

{path_mappings[:1000]}...

## Common Patterns

{common_patterns[:500]}...

Write Rego deny rules that check the attestation structure. Use the paths and patterns from the documentation above."""
        
        return system_prompt


class PathValidator:
    """Validate that Rego code uses paths from documentation."""
    
    def __init__(self, doc_extractor: DocContentExtractor):
        self.doc_extractor = doc_extractor
        self.valid_paths = self._extract_all_paths()
    
    def _extract_all_paths(self) -> set:
        """Extract all valid paths from documentation."""
        paths = set()
        
        # Extract from path mappings
        mappings = self.doc_extractor.extract_path_mappings()
        paths.update(mappings.values())
        
        # Extract from code examples
        content = self.doc_extractor.content
        path_pattern = r"`([a-zA-Z_][a-zA-Z0-9_.]*(\[[^\]]*\])?)`"
        matches = re.findall(path_pattern, content)
        for match, _ in matches:
            paths.add(match)
        
        return paths
    
    def validate_rego_paths(self, rego_code: str) -> Tuple[bool, List[str]]:
        """Validate that all paths in Rego code are documented."""
        errors = []
        
        # Extract paths from Rego code
        # Look for patterns like: attestation.statement.predicate...
        path_pattern = r"([a-zA-Z_][a-zA-Z0-9_.]*(?:\[[^\]]*\])?)"
        used_paths = set(re.findall(path_pattern, rego_code))
        
        # Filter to only paths that look like JSON paths (contain dots)
        json_paths = {p for p in used_paths if '.' in p and not p.startswith('input.')}
        
        # Check each path (simplified - would need more sophisticated parsing)
        for path in json_paths:
            # Check if path or a prefix is in valid paths
            if not any(path.startswith(valid) or valid.startswith(path) for valid in self.valid_paths):
                # Allow some common patterns
                if not any(skip in path for skip in ['task.', 'attestation.', 'result.', 'input.']):
                    errors.append(f"Path '{path}' not found in documentation")
        
        return len(errors) == 0, errors


class TrainingDataGenerator:
    """Generate training data with validation."""
    
    def __init__(self):
        self.doc_extractor = DocContentExtractor()
        self.path_validator = PathValidator(self.doc_extractor)
        self.test_definitions = load_test_case_definitions()
    
    def generate_system_prompt(self) -> str:
        """Generate system prompt from documentation."""
        return self.doc_extractor.generate_system_prompt()
    
    def format_assistant_response(self, rego_code: str, explanation: Optional[str] = None) -> str:
        """Format Rego code as assistant response."""
        if not explanation:
            explanation = self._generate_explanation(rego_code)
        
        return f"""```rego
{rego_code}
```

{explanation}"""
    
    def _generate_explanation(self, rego_code: str) -> str:
        """Generate explanation for Rego code."""
        # Simple explanation generation
        # In practice, this could use LLM or template-based approach
        return "This rule validates the requirement by checking the attestation structure."
    
    def validate_example(self, natural_language: str, rego_code: str) -> ValidationResult:
        """Validate a training example."""
        # Format as assistant response
        assistant_content = self.format_assistant_response(rego_code)
        
        # Validate paths
        paths_valid, path_errors = self.path_validator.validate_rego_paths(rego_code)
        if not paths_valid:
            return ValidationResult(
                passed=False,
                errors=path_errors,
                test_results=[]
            )
        
        # Validate functionality
        result = validate_training_example(natural_language, assistant_content)
        return result
    
    def generate_and_validate(self, natural_language: str, rego_code: str, 
                             auto_add: bool = False) -> Tuple[bool, str]:
        """Generate and validate a training example."""
        # Validate
        result = self.validate_example(natural_language, rego_code)
        
        if not result.passed:
            error_msg = "\n".join(result.errors)
            return False, f"Validation failed:\n{error_msg}"
        
        # Format complete example
        system_prompt = self.generate_system_prompt()
        assistant_content = self.format_assistant_response(rego_code)
        
        # Add to training data if requested
        if auto_add:
            add_to_training_data(natural_language, assistant_content)
            return True, "Added to training data"
        else:
            return True, "Validation passed (not added - use --add flag)"
    
    def batch_validate(self, examples: List[Tuple[str, str]]) -> Dict:
        """Validate multiple examples."""
        results = {
            "passed": [],
            "failed": [],
            "total": len(examples)
        }
        
        for natural_lang, rego_code in examples:
            success, message = self.generate_and_validate(natural_lang, rego_code)
            if success:
                results["passed"].append({
                    "natural_language": natural_lang,
                    "message": message
                })
            else:
                results["failed"].append({
                    "natural_language": natural_lang,
                    "error": message
                })
        
        return results


def main():
    """CLI interface."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate and validate training data")
    parser.add_argument("--natural-language", required=True,
                       help="Natural language policy requirement")
    parser.add_argument("--rego-file", required=True,
                       help="File containing Rego code")
    parser.add_argument("--add", action="store_true",
                       help="Add to training data if validation passes")
    parser.add_argument("--batch", help="JSON file with batch of examples")
    
    args = parser.parse_args()
    
    generator = TrainingDataGenerator()
    
    if args.batch:
        # Batch processing
        with open(args.batch) as f:
            examples = json.load(f)
        
        results = generator.batch_validate(examples)
        print(f"Batch validation: {len(results['passed'])}/{results['total']} passed")
        
        if results["failed"]:
            print("\nFailed examples:")
            for failed in results["failed"]:
                print(f"  - {failed['natural_language']}: {failed['error']}")
    else:
        # Single example
        with open(args.rego_file) as f:
            rego_code = f.read()
        
        success, message = generator.generate_and_validate(
            args.natural_language,
            rego_code,
            auto_add=args.add
        )
        
        if success:
            print(f"✅ {message}")
            sys.exit(0)
        else:
            print(f"❌ {message}")
            sys.exit(1)


if __name__ == "__main__":
    main()
