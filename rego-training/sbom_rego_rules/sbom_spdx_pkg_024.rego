#
# METADATA
# title: Verify all packages in the SPDX SBOM have checksums with valid algorithm.
# description: >-
#   Verify all packages in the SPDX SBOM have checksums with valid algorithm.
# custom:
#   short_name: sbom_spdx_pkg_024
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_024

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some chk in pkg.checksums
    not chk.algorithm
    result := sprintf("Package %s has checksum with no algorithm", [pkg.name])
}
