#
# METADATA
# title: Verify all packages in the SPDX SBOM have a SHA256 checksum.
# description: >-
#   Verify all packages in the SPDX SBOM have a SHA256 checksum.
# custom:
#   short_name: sbom_spdx_pkg_017
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_017

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    count([chk | some chk in pkg.checksums; chk.algorithm == "SHA256"]) == 0
    result := sprintf("Package %s has no SHA256 checksum", [pkg.name])
}
