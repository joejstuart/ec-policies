#
# METADATA
# title: Verify all packages in the SPDX SBOM have a valid downloadLocation format.
# description: >-
#   Verify all packages in the SPDX SBOM have a valid downloadLocation format.
# custom:
#   short_name: sbom_spdx_pkg_027
#   failure_msg: Policy validation failed
#
package sbom_spdx_pkg_027

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some pkg in sbom.packages
    pkg.downloadLocation != "NOASSERTION"
    not startswith(pkg.downloadLocation, "http")
    not startswith(pkg.downloadLocation, "git+")
    result := sprintf("Package %s has invalid downloadLocation format: %s", [pkg.name, pkg.downloadLocation])
}
