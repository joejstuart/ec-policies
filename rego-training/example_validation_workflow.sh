#!/bin/bash
# Example workflow for validating and adding Rego training examples

set -e

echo "=== Rego Training Data Validation Workflow ==="
echo ""

# Example 1: Validate a candidate Rego file
echo "Example 1: Validating candidate Rego code"
echo "-------------------------------------------"

# Create a test candidate file
cat > /tmp/candidate_prefetch.rego << 'EOF'
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildDefinition.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
EOF

# Validate it
echo "Validating candidate Rego..."
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task in the PipelineRun attestation was not invoked with the 'permissive' mode parameter." \
  /tmp/candidate_prefetch.rego || echo "Validation failed (expected if OPA not installed or test cases not matching)"

echo ""
echo "Example 2: Validating entire training file"
echo "-------------------------------------------"
echo "To validate all examples in data/qwen3-training-data.jsonl:"
echo "  python3 validate_and_add_training.py --validate-file data/qwen3-training-data.jsonl"
echo ""

echo "Example 3: Validate and add if passes"
echo "--------------------------------------"
echo "To validate and automatically add to training data:"
echo "  python3 validate_and_add_training.py \\"
echo "    --validate \"<natural language>\" candidate.rego \\"
echo "    --add-if-valid"
echo ""

echo "=== Workflow Complete ==="
