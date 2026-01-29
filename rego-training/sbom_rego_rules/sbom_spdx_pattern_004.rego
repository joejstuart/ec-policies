#
# METADATA
# title: Verify all packages in the SPDX SBOM have supplier starting with 'Organization:' or 'Person:'.
# description: >-
#   Verify all packages in the SPDX SBOM have supplier starting with 'Organization:' or 'Person:'.
# custom:
#   short_name: sbom_spdx_pattern_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_pattern_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.supplier != "NOASSERTION"
    not startswith(pkg.supplier, "Organization:")
    not startswith(pkg.supplier, "Person:")
    result := sprintf("Package %s has invalid supplier format: %s", [pkg.name, pkg.supplier])
}
