#
# METADATA
# title: Verify all packages in the SPDX SBOM with filesAnalyzed true have a packageVerificationCode.
# description: >-
#   Verify all packages in the SPDX SBOM with filesAnalyzed true have a packageVerificationCode.
# custom:
#   short_name: sbom_spdx_pkg_018
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_018

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.filesAnalyzed == true
    not pkg.packageVerificationCode
    result := sprintf("Package %s has filesAnalyzed true but no packageVerificationCode", [pkg.name])
}
