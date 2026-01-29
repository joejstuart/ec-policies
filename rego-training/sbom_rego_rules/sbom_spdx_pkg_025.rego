#
# METADATA
# title: Verify all packages in the SPDX SBOM have checksums with valid checksumValue.
# description: >-
#   Verify all packages in the SPDX SBOM have checksums with valid checksumValue.
# custom:
#   short_name: sbom_spdx_pkg_025
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_025

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    some chk in pkg.checksums
    not chk.checksumValue
    result := sprintf("Package %s has checksum with no checksumValue", [pkg.name])
}
