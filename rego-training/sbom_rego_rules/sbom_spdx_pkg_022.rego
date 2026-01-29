#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with valid referenceType.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with valid referenceType.
# custom:
#   short_name: sbom_spdx_pkg_022
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_022

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    not ref.referenceType
    result := sprintf("Package %s has external reference with no referenceType", [pkg.name])
}
