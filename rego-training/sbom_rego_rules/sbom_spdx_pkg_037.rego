#
# METADATA
# title: Verify all packages in the SPDX SBOM have at least one checksum algorithm in ['SHA1', 'SHA256', 'MD5'].
# description: >-
#   Verify all packages in the SPDX SBOM have at least one checksum algorithm in ['SHA1', 'SHA256', 'MD5'].
# custom:
#   short_name: sbom_spdx_pkg_037
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_037

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    valid_algorithms := {chk.algorithm | some chk in pkg.checksums; chk.algorithm in ["SHA1", "SHA256", "MD5"]}
    count(valid_algorithms) == 0
    result := sprintf("Package %s has no valid checksum algorithm", [pkg.name])
}
