#
# METADATA
# title: Verify all packages in the SPDX SBOM with annotations have valid annotation format.
# description: >-
#   Verify all packages in the SPDX SBOM with annotations have valid annotation format.
# custom:
#   short_name: sbom_spdx_adv_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some annotation in pkg.annotations
    not annotation.annotator
    result := sprintf("Package %s has annotation with no annotator", [pkg.name])
}
