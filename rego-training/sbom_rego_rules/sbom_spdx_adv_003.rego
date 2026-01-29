#
# METADATA
# title: Verify all packages in the SPDX SBOM with annotations have annotationType.
# description: >-
#   Verify all packages in the SPDX SBOM with annotations have annotationType.
# custom:
#   short_name: sbom_spdx_adv_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some annotation in pkg.annotations
    not annotation.annotationType
    result := sprintf("Package %s has annotation with no annotationType", [pkg.name])
}
