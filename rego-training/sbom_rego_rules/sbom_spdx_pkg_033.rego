#
# METADATA
# title: Verify all packages in the SPDX SBOM have PURL external references starting with 'pkg:'.
# description: >-
#   Verify all packages in the SPDX SBOM have PURL external references starting with 'pkg:'.
# custom:
#   short_name: sbom_spdx_pkg_033
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_033

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "purl"
    not startswith(ref.referenceLocator, "pkg:")
    result := sprintf("Package %s has invalid PURL format: %s", [pkg.name, ref.referenceLocator])
}
