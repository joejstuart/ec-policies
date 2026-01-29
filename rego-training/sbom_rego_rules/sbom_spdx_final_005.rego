#
# METADATA
# title: Verify all packages in the SPDX SBOM have versionInfo not equal to empty string.
# description: >-
#   Verify all packages in the SPDX SBOM have versionInfo not equal to empty string.
# custom:
#   short_name: sbom_spdx_final_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_005

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
