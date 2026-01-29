#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid SPDXID format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid SPDXID format.
# custom:
#   short_name: sbom_spdx_pkg_020
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_020

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    not startswith(pkg.SPDXID, "SPDXRef-")
    result := sprintf("Package %s has invalid SPDXID format: %s", [pkg.name, pkg.SPDXID])
}
