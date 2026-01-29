#
# METADATA
# title: Verify the SPDX SBOM has packages with at least one having a PURL containing 'golang'.
# description: >-
#   Verify the SPDX SBOM has packages with at least one having a PURL containing 'golang'.
# custom:
#   short_name: sbom_spdx_final_007
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    golang_purls := count([ref | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == "purl"; contains(ref.referenceLocator, "golang")])
    golang_purls == 0
    result := "SPDX SBOM has no packages with Golang PURLs"
}
