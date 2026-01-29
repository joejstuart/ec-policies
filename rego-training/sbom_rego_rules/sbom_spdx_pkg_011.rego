#
# METADATA
# title: Verify all packages in the SPDX SBOM have sourceInfo.
# description: >-
#   Verify all packages in the SPDX SBOM have sourceInfo.
# custom:
#   short_name: sbom_spdx_pkg_011
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_011

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    not pkg.sourceInfo
    result := sprintf("Package %s has no sourceInfo", [pkg.name])
}
