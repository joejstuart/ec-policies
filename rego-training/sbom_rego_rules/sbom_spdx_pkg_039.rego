#
# METADATA
# title: Verify all packages in the SPDX SBOM have checksums with unique algorithms.
# description: >-
#   Verify all packages in the SPDX SBOM have checksums with unique algorithms.
# custom:
#   short_name: sbom_spdx_pkg_039
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_039

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    chk_algorithms := {chk.algorithm | some chk in pkg.checksums}
    count(chk_algorithms) != count(pkg.checksums)
    result := sprintf("Package %s has duplicate checksum algorithms", [pkg.name])
}
