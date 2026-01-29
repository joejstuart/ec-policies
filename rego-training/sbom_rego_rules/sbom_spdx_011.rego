#
# METADATA
# title: Verify no packages in the SPDX SBOM have external references with type 'cpe23Type'.
# description: >-
#   Verify no packages in the SPDX SBOM have external references with type 'cpe23Type'.
# custom:
#   short_name: sbom_spdx_011
#   failure_msg: Policy validation failed
#
package sbom_spdx_011

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some ref in pkg.externalRefs
    ref.referenceType == "cpe23Type"
    result := sprintf("Package %s has disallowed CPE reference: %s", [pkg.name, ref.referenceLocator])
}
