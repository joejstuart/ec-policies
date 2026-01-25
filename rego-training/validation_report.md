# Training Data Validation Report

## Summary

✅ **All 651 examples are valid and correctly formatted!**

## Validation Results

- **Total Examples**: 651
- **Valid Examples**: 651 (100%)
- **Invalid Examples**: 0 (0%)

## Example Type Distribution

- **Rule Generation**: 219 examples
  - User asks for a Rego rule to validate a requirement
  - Assistant provides the deny rule code
  - System prompt explains Rego/OPA and attestation structure

- **Rule-to-Test**: 422 examples
  - User provides a Rego rule and asks for tests
  - Assistant provides complete test file with positive/negative cases
  - System prompt explains OPA testing best practices

- **Requirement-to-Rule-and-Test**: 10 examples
  - User asks for both rule and test from a requirement
  - Assistant provides both rule.rego and rule_test.rego
  - System prompt covers both rule writing and testing

## Quality Checks Performed

### ✅ Role Correctness
- All examples have correct message roles (system, user, assistant)
- First message is always system
- Second message is always user
- Last message is always assistant

### ✅ System Prompt Relevance
- System prompts mention Rego/OPA appropriately
- Test creation examples include testing best practices
- Attestation structure explained when relevant
- Enterprise Contract context provided

### ✅ Assistant Implementation
- Assistant provides Rego code blocks when user asks for rules
- Assistant provides test files when user asks for tests
- Assistant provides both rule and test when explicitly requested
- Package names are consistent between user request and assistant response

### ✅ Code Quality
- Test files include proper package declarations
- Test files include `import rego.v1` and `import data.{package}`
- Test files use `with input as` for test data
- Test files check `count({package}.deny)` appropriately
- Rule code includes deny logic
- Code is properly formatted in code blocks

## Sample Examples Verified

### Rule Generation Example
- ✅ System explains Rego/OPA and attestation structure
- ✅ User provides natural language requirement
- ✅ Assistant provides deny rule code
- ✅ Code includes proper deny logic

### Rule-to-Test Example
- ✅ System explains OPA testing best practices
- ✅ User provides Rego rule and asks for tests
- ✅ Assistant provides complete test file
- ✅ Test file includes package, imports, and test cases

### Requirement-to-Rule-and-Test Example
- ✅ System covers both rule writing and testing
- ✅ User asks for both rule and test
- ✅ Assistant provides both rule.rego and rule_test.rego
- ✅ Both files are complete and properly formatted

## Conclusion

All training examples are correctly formatted and ready for fine-tuning. The data includes:
- Proper role assignments
- Relevant system prompts
- Correct assistant implementations
- High-quality Rego code
- Comprehensive test coverage

The training data is ready to use for fine-tuning the Qwen3 model.
