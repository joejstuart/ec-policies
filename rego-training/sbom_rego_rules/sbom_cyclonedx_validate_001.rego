#
# METADATA
# title: Verify all components in the CycloneDX SBOM have version format matching semver when applicable.
# description: >-
#   Verify all components in the CycloneDX SBOM have version format matching semver when applicable.
# custom:
#   short_name: sbom_cyclonedx_validate_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_validate_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.version
    contains(comp.version, ".")
    version_parts := split(comp.version, ".")
    count(version_parts) < 2
    result := sprintf("Component %s has invalid semver format: %s", [comp.name, comp.version])
}
