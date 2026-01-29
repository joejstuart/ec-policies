#
# METADATA
# title: Verify all packages in the SPDX SBOM have a non-empty SPDXID.
# description: >-
#   Verify all packages in the SPDX SBOM have a non-empty SPDXID.
# custom:
#   short_name: sbom_spdx_pkg_043
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_043

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.SPDXID == ""
    result := sprintf("Package %s has empty SPDXID", [pkg.name])
}
