#
# METADATA
# title: Verify no packages in the SPDX SBOM have external references with referenceCategory 'SECURITY'.
# description: >-
#   Verify no packages in the SPDX SBOM have external references with referenceCategory 'SECURITY'.
# custom:
#   short_name: sbom_spdx_complex_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceCategory == "SECURITY"
    result := sprintf("Package %s has SECURITY external reference: %s", [pkg.name, ref.referenceLocator])
}
