#
# METADATA
# title: Verify the SPDX SBOM creationInfo has a valid licenseListVersion.
# description: >-
#   Verify the SPDX SBOM creationInfo has a valid licenseListVersion.
# custom:
#   short_name: sbom_spdx_doc_012
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_012

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not sbom.creationInfo.licenseListVersion
    result := "SPDX SBOM creationInfo has no licenseListVersion"
}
