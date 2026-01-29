#
# METADATA
# title: Verify all packages in the SPDX SBOM have versionInfo not starting with 'v' when it contains numbers.
# description: >-
#   Verify all packages in the SPDX SBOM have versionInfo not starting with 'v' when it contains numbers.
# custom:
#   short_name: sbom_spdx_pattern_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_pattern_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    contains(pkg.versionInfo, "0")
    contains(pkg.versionInfo, "1")
    contains(pkg.versionInfo, "2")
    contains(pkg.versionInfo, "3")
    contains(pkg.versionInfo, "4")
    contains(pkg.versionInfo, "5")
    contains(pkg.versionInfo, "6")
    contains(pkg.versionInfo, "7")
    contains(pkg.versionInfo, "8")
    contains(pkg.versionInfo, "9")
    startswith(pkg.versionInfo, "v")
    result := sprintf("Package %s has versionInfo starting with 'v': %s", [pkg.name, pkg.versionInfo])
}
