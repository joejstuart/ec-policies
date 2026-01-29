#
# METADATA
# title: Verify no packages in the SPDX SBOM have version '(devel)'.
# description: >-
#   Verify no packages in the SPDX SBOM have version '(devel)'.
# custom:
#   short_name: sbom_spdx_006
#   failure_msg: Policy validation failed
#
package sbom_spdx_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.versionInfo == "(devel)"
    result := sprintf("Package %s has development version", [pkg.name])
}
