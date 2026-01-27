# Training Data Variation Analysis

## Current Coverage

### File Types (Good Diversity)
- **Text files**: 143 examples (27%)
- **Markdown**: 82 examples (16%)
- **Python**: 81 examples (15%)
- **JSON**: 81 examples (15%)
- **YAML**: 63 examples (12%)
- **Go**: 45 examples (9%)
- **Rego**: 30 examples (6%)

**Assessment**: ✅ Good diversity across common file types

### Operation Types
- **Add/Insert**: 225 examples (43%)
- **Replace/Update**: 150 examples (29%)
- **Delete/Remove**: 45 examples (9%)
- **Create**: 45 examples (9%)
- **Edit/Modify**: 45 examples (9%)
- **Other**: 15 examples (3%)

**Assessment**: ⚠️ Some imbalance - heavy on "add" operations, lighter on delete/create

### Tool Call Patterns
- **Read + Write (edit)**: 465 examples (89%)
- **Write only (create)**: 45 examples (9%)
- **Read only (no-op)**: 15 examples (3%)

**Assessment**: ✅ Good coverage of edit workflow, but could use more create examples

### File Path Diversity
- **Unique paths**: 38 different file paths
- **Path variety**: Mix of generic and specific names

**Assessment**: ✅ Good diversity

### Content Complexity
- **Average length**: 58 characters
- **Min**: 26 characters
- **Max**: 198 characters

**Assessment**: ⚠️ Files are relatively small - may not cover large file scenarios

## What's Covered Well

✅ **Basic Operations**: Line replacement, insertion, deletion, text replacement
✅ **Code Editing**: Go, Python, Rego examples
✅ **Config Files**: YAML, JSON editing
✅ **Documentation**: Markdown editing
✅ **Edge Cases**: Ambiguous instructions, no-ops, partial matches
✅ **File Creation**: New file creation examples
✅ **Multiple File Types**: Good variety across languages/formats

## Potential Gaps

### 1. File Size Variations
**Issue**: Most examples use small files (avg 58 chars, max 198 chars)

**Recommendation**: Add examples with:
- Larger files (500+ lines)
- Very small files (1-2 lines)
- Empty files (already covered)

### 2. Instruction Phrasing Variations
**Issue**: Instructions may be too similar in structure

**Recommendation**: Add variations like:
- "Update the file..." vs "Edit the file..." vs "Modify..."
- "Add X to Y" vs "Insert X after Y" vs "Place X in Y"
- More natural language variations

### 3. Error Handling
**Issue**: No examples of error scenarios

**Recommendation**: Add examples for:
- File not found errors
- Invalid file paths
- Permission errors
- Malformed content

### 4. Multi-File Operations
**Issue**: All examples operate on single files

**Recommendation**: Add examples for:
- Reading multiple files
- Comparing files
- Copying content between files

### 5. Complex Nested Structures
**Issue**: Limited examples of deeply nested edits

**Recommendation**: Add examples for:
- Deeply nested JSON/YAML
- Multi-level code structures
- Complex markdown with nested lists

### 6. Delete Operations
**Issue**: Only 45 delete examples (9% of total)

**Recommendation**: Increase delete operation examples:
- Delete lines
- Delete sections
- Delete files
- Delete nested elements

### 7. Path Variations
**Issue**: Limited path complexity

**Recommendation**: Add examples with:
- Nested paths: `dir/subdir/file.txt`
- Absolute paths: `/home/user/file.txt`
- Paths with spaces: `my file.txt`
- Paths with special chars: `file-v1.2.txt`

## Recommendations

### High Priority

1. **Add more file creation examples** (currently 9%)
   - Target: 15-20% of examples
   - Add variations: create with template, create from scratch, create with validation

2. **Increase delete operation examples** (currently 9%)
   - Target: 15% of examples
   - Add: delete lines, delete sections, delete nested elements

3. **Add larger file examples**
   - Target: 10-15 examples with 200+ line files
   - Helps model learn to handle context limits

### Medium Priority

4. **Add instruction phrasing variations**
   - Same operation, different wording
   - Helps model generalize to user language

5. **Add error handling examples**
   - File not found
   - Invalid operations
   - Helps model handle edge cases gracefully

### Low Priority

6. **Add multi-file operations**
   - Nice to have, but may be beyond scope for generic tool usage

7. **Add path complexity variations**
   - Nested paths, special characters
   - Helps model handle real-world file paths

## Current Assessment: **Good, but could be better**

### Strengths
- ✅ Good diversity of file types
- ✅ Covers basic operations well
- ✅ Includes edge cases (ambiguous, no-ops)
- ✅ Code editing examples for multiple languages
- ✅ File creation included

### Areas for Improvement
- ⚠️ Imbalance: Too many "add" operations, too few "delete"
- ⚠️ File sizes: Mostly small files, need larger examples
- ⚠️ Error handling: No error scenario examples
- ⚠️ Instruction variations: Could use more phrasing diversity

## Conclusion

**For a small model (<3B)**: The current 525 examples with 34 types is **adequate** but could benefit from:
- More delete operations
- Larger file examples
- Error handling scenarios

**Recommendation**: The current dataset is good enough to start training, but consider adding 50-100 more examples focusing on:
1. Delete operations (20-30 examples)
2. Larger files (10-15 examples)
3. Error scenarios (10-15 examples)
4. Instruction variations (10-20 examples)

This would bring the total to ~600 examples, which is still reasonable for a small model.
