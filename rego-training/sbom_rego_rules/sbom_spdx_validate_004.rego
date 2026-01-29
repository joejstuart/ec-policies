#
# METADATA
# title: Verify all packages in the SPDX SBOM have packageVerificationCodeValue with valid length.
# description: >-
#   Verify all packages in the SPDX SBOM have packageVerificationCodeValue with valid length.
# custom:
#   short_name: sbom_spdx_validate_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_validate_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.packageVerificationCode
    count(pkg.packageVerificationCode.packageVerificationCodeValue) != 40
    result := sprintf("Package %s has packageVerificationCodeValue with invalid length: %d", [pkg.name, count(pkg.packageVerificationCode.packageVerificationCodeValue)])
}
