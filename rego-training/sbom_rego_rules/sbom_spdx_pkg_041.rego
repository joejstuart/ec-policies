#
# METADATA
# title: Verify all packages in the SPDX SBOM have sourceInfo containing 'acquired'.
# description: >-
#   Verify all packages in the SPDX SBOM have sourceInfo containing 'acquired'.
# custom:
#   short_name: sbom_spdx_pkg_041
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_041

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.sourceInfo
    not contains(pkg.sourceInfo, "acquired")
    result := sprintf("Package %s sourceInfo does not contain 'acquired': %s", [pkg.name, pkg.sourceInfo])
}
