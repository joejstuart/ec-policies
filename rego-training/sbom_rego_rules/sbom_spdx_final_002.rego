#
# METADATA
# title: Verify all packages in the SPDX SBOM have downloadLocation not equal to empty string.
# description: >-
#   Verify all packages in the SPDX SBOM have downloadLocation not equal to empty string.
# custom:
#   short_name: sbom_spdx_final_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.downloadLocation == ""
    result := sprintf("Package %s has empty downloadLocation", [pkg.name])
}
