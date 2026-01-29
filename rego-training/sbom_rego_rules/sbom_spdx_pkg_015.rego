#
# METADATA
# title: Verify all packages in the SPDX SBOM have external references with category 'PACKAGE_MANAGER'.
# description: >-
#   Verify all packages in the SPDX SBOM have external references with category 'PACKAGE_MANAGER'.
# custom:
#   short_name: sbom_spdx_pkg_015
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_015

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count([ref | some ref in pkg.externalRefs; ref.referenceCategory == "PACKAGE_MANAGER"]) == 0
    result := sprintf("Package %s has no PACKAGE_MANAGER external reference", [pkg.name])
}
