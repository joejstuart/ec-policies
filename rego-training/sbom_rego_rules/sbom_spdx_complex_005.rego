#
# METADATA
# title: Verify the SPDX SBOM has at least one package with a PURL containing 'rpm'.
# description: >-
#   Verify the SPDX SBOM has at least one package with a PURL containing 'rpm'.
# custom:
#   short_name: sbom_spdx_complex_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    pkg_purls := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == "purl"}
    count([purl | some purl in pkg_purls; contains(purl, "rpm")]) == 0
    result := "SPDX SBOM has no package with RPM PURL"
}
