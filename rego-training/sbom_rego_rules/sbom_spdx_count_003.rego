#
# METADATA
# title: Verify all packages in the SPDX SBOM have at least 2 external references.
# description: >-
#   Verify all packages in the SPDX SBOM have at least 2 external references.
# custom:
#   short_name: sbom_spdx_count_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_count_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count(pkg.externalRefs) < 2
    result := sprintf("Package %s has only %d external references, expected at least 2", [pkg.name, count(pkg.externalRefs)])
}
