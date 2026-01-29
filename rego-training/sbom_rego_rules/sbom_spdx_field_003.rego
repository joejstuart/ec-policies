#
# METADATA
# title: Verify the SPDX SBOM creationInfo has licenseListVersion in format 'X.Y'.
# description: >-
#   Verify the SPDX SBOM creationInfo has licenseListVersion in format 'X.Y'.
# custom:
#   short_name: sbom_spdx_field_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_field_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    sbom.creationInfo.licenseListVersion
    not contains(sbom.creationInfo.licenseListVersion, ".")
    result := sprintf("SPDX SBOM licenseListVersion has invalid format: %s", [sbom.creationInfo.licenseListVersion])
}
