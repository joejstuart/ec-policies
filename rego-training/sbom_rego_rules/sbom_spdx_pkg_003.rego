#
# METADATA
# title: Verify all packages in the SPDX SBOM have a versionInfo.
# description: >-
#   Verify all packages in the SPDX SBOM have a versionInfo.
# custom:
#   short_name: sbom_spdx_pkg_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    not pkg.versionInfo
    result := sprintf("Package %s has no versionInfo", [pkg.name])
}
