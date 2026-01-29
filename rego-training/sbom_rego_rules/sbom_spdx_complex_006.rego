#
# METADATA
# title: Verify the SPDX SBOM has at least one package with a PURL containing 'golang'.
# description: >-
#   Verify the SPDX SBOM has at least one package with a PURL containing 'golang'.
# custom:
#   short_name: sbom_spdx_complex_006
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    pkg_purls := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == "purl"}
    count([purl | some purl in pkg_purls; contains(purl, "golang")]) == 0
    result := "SPDX SBOM has no package with Golang PURL"
}
