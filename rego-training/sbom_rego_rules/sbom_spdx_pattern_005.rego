#
# METADATA
# title: Verify all packages in the SPDX SBOM have originator starting with 'Organization:' or 'Person:'.
# description: >-
#   Verify all packages in the SPDX SBOM have originator starting with 'Organization:' or 'Person:'.
# custom:
#   short_name: sbom_spdx_pattern_005
#   failure_msg: Policy validation failed
#
package sbom_spdx_pattern_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.originator != "NOASSERTION"
    not startswith(pkg.originator, "Organization:")
    not startswith(pkg.originator, "Person:")
    result := sprintf("Package %s has invalid originator format: %s", [pkg.name, pkg.originator])
}
