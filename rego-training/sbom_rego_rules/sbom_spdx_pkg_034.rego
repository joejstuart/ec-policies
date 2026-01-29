#
# METADATA
# title: Verify all packages in the SPDX SBOM have CPE external references starting with 'cpe:'.
# description: >-
#   Verify all packages in the SPDX SBOM have CPE external references starting with 'cpe:'.
# custom:
#   short_name: sbom_spdx_pkg_034
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_034

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "cpe23Type"
    not startswith(ref.referenceLocator, "cpe:")
    result := sprintf("Package %s has invalid CPE format: %s", [pkg.name, ref.referenceLocator])
}
