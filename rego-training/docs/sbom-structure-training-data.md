# SBOM Structure Training Data

This document maps natural language descriptions to JSON paths in the SBOM structure, enabling models to understand how to navigate SBOM data when writing policy rules.

## Input Structure Overview

SBOMs (Software Bill of Materials) are accessed directly from attestations by checking the `predicateType`. SBOMs can be in two formats: SPDX or CycloneDX. **Important**: Use pure Rego without importing libraries from this repo.

The input to policy rules follows this structure:
```json
{
  "attestations": [
    {
      "statement": {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://spdx.dev/Document",
        "predicate": {
          "SPDXID": "SPDXRef-DOCUMENT",
          "packages": [...],
          "files": [...],
          "name": "...",
          "creationInfo": {...}
        }
      }
    },
    {
      "statement": {
        "predicateType": "https://cyclonedx.org/bom",
        "predicate": {
          "bomFormat": "CycloneDX",
          "components": [...],
          "metadata": {...}
        }
      }
    }
  ]
}
```

## Key Path Mappings

### Top-Level Navigation

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "all attestations" | `input.attestations` | Array of all attestations |
| "each attestation" | `some attestation in input.attestations` | Iterate over attestations |
| "the statement in an attestation" | `attestation.statement` | The in-toto statement object |
| "the predicate type" | `attestation.statement.predicateType` | Type of predicate (e.g., "https://spdx.dev/Document", "https://cyclonedx.org/bom") |
| "the predicate" | `attestation.statement.predicate` | The predicate data containing SBOM information |

### Accessing SBOMs from Attestations (Pure Rego)

| Natural Language | Rego Code | Description |
|-----------------|-----------|-------------|
| "each SPDX SBOM" | `some att in input.attestations; statement := att.statement; statement.predicateType == "https://spdx.dev/Document"; sbom := statement.predicate` | Access SPDX SBOM directly from attestation |
| "each CycloneDX SBOM" | `some att in input.attestations; statement := att.statement; statement.predicateType == "https://cyclonedx.org/bom"; sbom := statement.predicate` | Access CycloneDX SBOM directly from attestation |
| "SPDX SBOM predicate" | `statement.predicate` where `statement.predicateType == "https://spdx.dev/Document"` | The SPDX SBOM data (packages, files, etc.) |
| "CycloneDX SBOM predicate" | `statement.predicate` where `statement.predicateType == "https://cyclonedx.org/bom"` | The CycloneDX SBOM data (components, metadata, etc.) |

**Pattern for accessing SPDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://spdx.dev/Document"
sbom := statement.predicate
# Now use sbom.packages, sbom.files, etc.
```

**Pattern for accessing CycloneDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://cyclonedx.org/bom"
sbom := statement.predicate
# Now use sbom.components, sbom.metadata, etc.
```

### SPDX SBOM Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "SPDX document ID" | `s.SPDXID` | Document identifier (typically "SPDXRef-DOCUMENT") |
| "SPDX document name" | `s.name` | Name of the SBOM document (usually image reference) |
| "SPDX version" | `s.spdxVersion` | SPDX specification version (e.g., "SPDX-2.3") |
| "SPDX packages" | `s.packages` | Array of packages in the SPDX SBOM |
| "SPDX files" | `s.files` | Array of files in the SPDX SBOM |
| "creation info" | `s.creationInfo` | Creation metadata (created timestamp, creators, license list version) |
| "creation timestamp" | `s.creationInfo.created` | ISO 8601 timestamp when SBOM was created |
| "creators" | `s.creationInfo.creators` | Array of creator strings (Organization, Tool, Person) |
| "data license" | `s.dataLicense` | License for the SBOM data (e.g., "CC0-1.0") |
| "document namespace" | `s.documentNamespace` | Unique namespace for the document |

### SPDX Package Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "each package in SPDX SBOM" | `some pkg in s.packages` | Iterate over packages |
| "package SPDX ID" | `pkg.SPDXID` | Unique identifier for the package |
| "package name" | `pkg.name` | Name of the package |
| "package version" | `pkg.versionInfo` | Version of the package |
| "package supplier" | `pkg.supplier` | Supplier of the package (e.g., "Organization: Red Hat, Inc.") |
| "package originator" | `pkg.originator` | Originator of the package |
| "package license declared" | `pkg.licenseDeclared` | License declared for the package |
| "package license concluded" | `pkg.licenseConcluded` | License concluded for the package |
| "package download location" | `pkg.downloadLocation` | Download location (often "NOASSERTION") |
| "package external references" | `pkg.externalRefs` | Array of external references (PURL, CPE, etc.) |
| "package files analyzed" | `pkg.filesAnalyzed` | Boolean indicating if files were analyzed |
| "package verification code" | `pkg.packageVerificationCode` | Package verification code object |
| "package verification code value" | `pkg.packageVerificationCode.packageVerificationCodeValue` | SHA1 hash of package files |
| "package source info" | `pkg.sourceInfo` | Source information about how package was acquired |
| "package copyright text" | `pkg.copyrightText` | Copyright text (often "NOASSERTION") |

### SPDX External References

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "each external reference" | `some ref in pkg.externalRefs` | Iterate over external references |
| "reference type" | `ref.referenceType` | Type of reference (e.g., "purl", "cpe23Type") |
| "reference category" | `ref.referenceCategory` | Category of reference (e.g., "PACKAGE_MANAGER", "SECURITY") |
| "reference locator" | `ref.referenceLocator` | The actual reference value (PURL, CPE, etc.) |
| "PURL reference" | `ref.referenceType == "purl"` | Package URL reference |
| "CPE reference" | `ref.referenceType == "cpe23Type"` | CPE 2.3 reference |

### CycloneDX SBOM Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "CycloneDX BOM format" | `s.bomFormat` | Format identifier (e.g., "CycloneDX") |
| "CycloneDX spec version" | `s.specVersion` | CycloneDX specification version |
| "CycloneDX components" | `s.components` | Array of components in the CycloneDX SBOM |
| "CycloneDX metadata" | `s.metadata` | Metadata about the BOM |
| "CycloneDX dependencies" | `s.dependencies` | Array of dependency relationships |

### CycloneDX Component Structure

| Natural Language | JSON Path | Description |
|-----------------|-----------|-------------|
| "each component in CycloneDX SBOM" | `some comp in s.components` | Iterate over components |
| "component type" | `comp.type` | Type of component (e.g., "library", "application", "container") |
| "component name" | `comp.name` | Name of the component |
| "component version" | `comp.version` | Version of the component |
| "component purl" | `comp.purl` | Package URL for the component |
| "component bom-ref" | `comp.bom-ref` | Unique reference identifier |
| "component licenses" | `comp.licenses` | Array of license information |
| "component external references" | `comp.externalReferences` | Array of external references |

## Common Patterns

### Pattern 1: Check if SPDX SBOM has packages

**Natural Language:**
"Verify the SPDX SBOM contains packages."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.packages) == 0
    result := "SPDX SBOM has no packages"
}
```

### Pattern 2: Check package external references

**Natural Language:**
"Verify all packages in the SPDX SBOM have allowed external references."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "purl"
    not ref.referenceLocator in allowed_purls
    result := sprintf("Package %s has disallowed PURL: %s", [pkg.name, ref.referenceLocator])
}
```

### Pattern 3: Check package version

**Natural Language:**
"Verify no packages in the SPDX SBOM have version '(devel)'."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.versionInfo == "(devel)"
    result := sprintf("Package %s has development version", [pkg.name])
}
```

### Pattern 4: Check SPDX SBOM validity

**Natural Language:**
"Verify the SPDX SBOM is valid according to the schema."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some violation in json.match_schema(sbom, schema_2_3)[1]
    error := violation.error
    result := sprintf("SPDX SBOM is not valid: %s", [error])
}
```

### Pattern 5: Check package supplier

**Natural Language:**
"Verify all packages in the SPDX SBOM have a supplier."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.supplier == "NOASSERTION"
    result := sprintf("Package %s has no supplier", [pkg.name])
}
```

### Pattern 6: Check package license

**Natural Language:**
"Verify all packages in the SPDX SBOM have a declared license."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.licenseDeclared == "NOASSERTION"
    result := sprintf("Package %s has no declared license", [pkg.name])
}
```

### Pattern 7: Check CycloneDX component type

**Natural Language:**
"Verify all components in the CycloneDX SBOM are of type 'library'."

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.type != "library"
    result := sprintf("Component %s has type %s, expected library", [comp.name, comp.type])
}
```

### Pattern 8: Check SBOM matches image

**Natural Language:**
"Verify the SPDX SBOM name matches the image being validated."

**Note**: This pattern requires image parsing which may need library functions. For pure Rego, you might check the SBOM name directly:
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    # Check SBOM name contains expected image reference
    not contains(sbom.name, expected_image_ref)
    result := sprintf("SBOM name %s does not match expected image", [sbom.name])
}
```

## Example Mappings

### Example 1: Check SPDX SBOM has packages

**Natural Language:**
"Verify the SPDX SBOM contains at least one package."

**JSON Path Navigation:**
1. Access attestations: `some att in input.attestations`
2. Get statement: `statement := att.statement`
3. Check predicate type: `statement.predicateType == "https://spdx.dev/Document"`
4. Get SBOM: `sbom := statement.predicate`
5. Check packages count: `count(sbom.packages) == 0`

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.packages) == 0
    result := "SPDX SBOM has no packages"
}
```

### Example 2: Check package PURL

**Natural Language:**
"Verify no packages in the SPDX SBOM use a disallowed PURL."

**JSON Path Navigation:**
1. Access attestations: `some att in input.attestations`
2. Get statement: `statement := att.statement`
3. Check predicate type: `statement.predicateType == "https://spdx.dev/Document"`
4. Get SBOM: `sbom := statement.predicate`
5. Access packages: `some pkg in sbom.packages`
6. Access external references: `some ref in pkg.externalRefs`
7. Check reference type: `ref.referenceType == "purl"`
8. Check reference locator: `ref.referenceLocator`

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "purl"
    not ref.referenceLocator in allowed_purls
    result := sprintf("Package %s has disallowed PURL: %s", [pkg.name, ref.referenceLocator])
}
```

### Example 3: Check package version format

**Natural Language:**
"Verify no packages in the SPDX SBOM have version '(devel)'."

**JSON Path Navigation:**
1. Access attestations: `some att in input.attestations`
2. Get statement: `statement := att.statement`
3. Check predicate type: `statement.predicateType == "https://spdx.dev/Document"`
4. Get SBOM: `sbom := statement.predicate`
5. Access packages: `some pkg in sbom.packages`
6. Check version: `pkg.versionInfo == "(devel)"`

**Rego Code Pattern:**
```rego
deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.versionInfo == "(devel)"
    result := sprintf("Package %s has development version", [pkg.name])
}
```

## Notes

1. **Pure Rego**: Use pure Rego without importing libraries from this repo. Access SBOMs directly from `input.attestations` by checking `predicateType`.

2. **SBOM Access Pattern**: Always use this pattern to access SBOMs:
   ```rego
   some att in input.attestations
   statement := att.statement
   statement.predicateType == "https://spdx.dev/Document"  # or "https://cyclonedx.org/bom"
   sbom := statement.predicate
   ```

3. **Multiple SBOMs**: An image may have multiple SBOMs (SPDX and/or CycloneDX). Iterate over all attestations when checking.

4. **Package Identification**: Packages are typically identified by PURL (Package URL) in `externalRefs` with `referenceType == "purl"`.

5. **No Library Imports**: Do not import `data.lib.sbom` or any other libraries from this repo. Use only standard Rego and direct attestation access.
