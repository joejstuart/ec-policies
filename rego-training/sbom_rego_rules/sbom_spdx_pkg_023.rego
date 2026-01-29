#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with valid referenceCategory.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with valid referenceCategory.
# custom:
#   short_name: sbom_spdx_pkg_023
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_023

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    not ref.referenceCategory
    result := sprintf("Package %s has external reference with no referenceCategory", [pkg.name])
}
