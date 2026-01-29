#
# METADATA
# title: Verify all packages in the SPDX SBOM with filesAnalyzed true have at least one file.
# description: >-
#   Verify all packages in the SPDX SBOM with filesAnalyzed true have at least one file.
# custom:
#   short_name: sbom_spdx_complex_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.filesAnalyzed == true
    count(sbom.files) == 0
    result := sprintf("Package %s has filesAnalyzed true but SBOM has no files", [pkg.name])
}
