#
# METADATA
# title: Verify the SPDX SBOM has at least one package with supplier containing 'Red Hat'.
# description: >-
#   Verify the SPDX SBOM has at least one package with supplier containing 'Red Hat'.
# custom:
#   short_name: sbom_spdx_final_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    suppliers := {pkg.supplier | some pkg in sbom.packages}
    count([supplier | some supplier in suppliers; contains(supplier, "Red Hat")]) == 0
    result := "SPDX SBOM has no packages with Red Hat supplier"
}
