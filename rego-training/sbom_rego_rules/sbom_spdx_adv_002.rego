#
# METADATA
# title: Verify all packages in the SPDX SBOM with annotations have annotationDate.
# description: >-
#   Verify all packages in the SPDX SBOM with annotations have annotationDate.
# custom:
#   short_name: sbom_spdx_adv_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some annotation in pkg.annotations
    not annotation.annotationDate
    result := sprintf("Package %s has annotation with no annotationDate", [pkg.name])
}
