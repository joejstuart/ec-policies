#
# METADATA
# title: Verify no packages in the SPDX SBOM have empty versionInfo.
# description: >-
#   Verify no packages in the SPDX SBOM have empty versionInfo.
# custom:
#   short_name: sbom_spdx_pkg_030
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_030

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.versionInfo == ""
    result := sprintf("Package %s has empty versionInfo", [pkg.name])
}
