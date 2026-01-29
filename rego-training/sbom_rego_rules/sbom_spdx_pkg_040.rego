#
# METADATA
# title: Verify all packages in the SPDX SBOM with packageVerificationCode have a non-empty value.
# description: >-
#   Verify all packages in the SPDX SBOM with packageVerificationCode have a non-empty value.
# custom:
#   short_name: sbom_spdx_pkg_040
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_040

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.packageVerificationCode
    pkg.packageVerificationCode.packageVerificationCodeValue == ""
    result := sprintf("Package %s has empty packageVerificationCode value", [pkg.name])
}
