package olm_release_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.olm_release

unpinned := "registry.io/repo/msd:no_digest"

unpinned_related_img := "registry.io/repo/msd:latest"

pinned0 := "registry.io/repository/image@sha256:dosa"

pinned1 := "registry.io/repository/image@sha256:cafe"

pinned2 := "registry.io/repository/image2@sha256:tea"

pinned3 := "registry.io/repository/image3@sha256:coffee"

component0 := {
	"name": "Unnamed",
	"containerImage": pinned0,
	"source": {},
}

component1 := {
	"name": "Unnamed",
	"containerImage": pinned1,
	"source": {},
}

component2 := {
	"name": "pinned_image2",
	"containerImage": pinned2,
	"source": {},
}

component3 := {
	"name": "pinned_image3",
	"containerImage": pinned3,
	"source": {},
}

unpinned_component := {
	"name": "unpinned_image",
	"containerImage": unpinned,
	"source": {},
}

manifest := {
	"apiVersion": "operators.coreos.com/v1alpha1",
	"kind": "ClusterServiceVersion",
	"metadata": {"annotations": {
		"containerImage": pinned1,
		"enclosurePicture": sprintf("%s,  %s", [pinned1, pinned2]),
		"features.operators.openshift.io/disconnected": "true",
		"features.operators.openshift.io/fips-compliant": "true",
		"features.operators.openshift.io/proxy-aware": "true",
		"features.operators.openshift.io/tls-profiles": "false",
		"features.operators.openshift.io/token-auth-aws": "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp": "false",
		"operators.openshift.io/valid-subscription": `["spam"]`,
		"alm-examples": `"endpoint": "http://example:4317" spam`,
		# regal ignore:line-length
		"features.operators.image": `{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"openshift-workload-availability","annotations":{"openshift.io/node-selector":""}}}`,
	}},
	"spec": {
		"version": "0.1.3",
		"relatedImages": [{"image": pinned1}],
		"install": {"spec": {"deployments": [{
			"metadata": {"annotations": {"docket": sprintf("%s\n  %s", [pinned1, pinned2])}},
			"spec": {"template": {
				"metadata": {"name": "c1"},
				"spec": {
					"containers": [{
						"name": "c1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_C1", "value": pinned1}],
					}],
					"initContainers": [{
						"name": "i1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_E1", "value": pinned1}],
					}],
				},
			}},
		}]}},
	},
	"not-metadata": {"annotations": {"something": pinned2}},
	"metadata-without-annotations": {"metadata": {}},
	"metadata-with-empty-annotations": {"metadata": {"annotations": {}}},
}

test_unpinned_snapshot_references_operator if {
	expected := {{
		"code": "olm_release.unpinned_snapshot_references",
		"msg": "The \"registry.io/repo/msd:no_digest\" image reference is not pinned in the input snapshot.",
		"term": "registry.io/repo/msd:no_digest",
	}}
	lib.assert_equal_results(olm_release.deny, expected) with input.snapshot.components as [unpinned_component, component1]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as unpinned_component.containerImage
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
}

test_unpinned_snapshot_references_different_input if {
	lib.assert_empty(olm_release.deny) with input.snapshot.components as [unpinned_component]
		with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as pinned2
}

test_unmapped_references_in_operator if {
	expected := {{
		"code": "olm_release.unmapped_references",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not in the snapshot or accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	lib.assert_equal_results(olm_release.deny, expected) with input.snapshot.components as [component1]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with data.rule_data as {"pipeline_intention": "release", "allowed_olm_image_registry_prefixes": ["registry.io"]}
		with data.rule_data.allowed_olm_resource_kinds as ["ClusterServiceVersion"]
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
		with input.image.config.Labels as {olm_release.manifestv1: "manifests/"}
}

test_unpinned_related_images if {
	expected_deny := {{
		"code": "olm_release.unpinned_related_images",
		"msg": "2 related images are not pinned with a digest: registry.io/repo/msd:latest, registry.io/repo/msd:latest.",
	}}

	lib.assert_equal_results(olm_release.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with input.snapshot.components as [component0]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_unpinned_image_partial
		with ec.oci.blob as _mock_unpinned_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

test_inaccessible_related_images if {
	expected_deny := {{
		"code": "olm_release.inaccessible_related_images",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" related image reference is not accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	lib.assert_equal_results(olm_release.deny, expected_deny) with data.rule_data.pipeline_intention as "release"
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with input.snapshot.components as [component1]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.blob as _mock_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

test_olm_ci_pipeline if {
	# Make sure no violations are thrown if it isn't a release pipeline
	# regal ignore:line-length
	lib.assert_equal(false, lib.pipeline_intention_match(rego.metadata.chain())) with data.rule_data as {"pipeline_intention": null}
}

mock_ec_oci_image_descriptor("registry.io/repository/image@sha256:cafe") := `{"config": {"digest": "sha256:cafe"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image3@sha256:coffee") := `{"config": {"digest": "sha256:coffee"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image2@sha256:tea") := false

mock_ec_oci_image_descriptor("registry.io/repo/msd:latest") := `{"config": {"digest": ""}}`

_related_images := [pinned1, pinned2, pinned3]

_unpinned_related_images := [unpinned_related_img]

_manifests_all := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm_release._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
	"registry.io/repository/image2@sha256:tea": {"config": {"digest": "sha256:tea"}},
	"registry.io/repository/image3@sha256:coffee": {"config": {"digest": "sha256:coffee"}},
}

_manifests_partial := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm_release._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
}

_manifests_unpinned := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm_release._related_images_oci_mime_type,
		"digest": "sha256:related_unpinned_blob_digest",
	}]},
	"registry.io/repository/image@sha256:dosa": {"config": {"digest": "sha256:dosa"}},
}

_blobs := {"registry.io/repository/image@sha256:related_blob_digest": json.marshal(_related_images)}

unpinned_blob_key := "registry.io/repository/image@sha256:related_unpinned_blob_digest"

_unpinned_blobs := {unpinned_blob_key: json.marshal(_unpinned_related_images)}

_mock_image_all(ref) := _manifests_all[ref]

_mock_image_partial(ref) := _manifests_partial[ref]

_mock_unpinned_image_partial(ref) := _manifests_unpinned[ref]

_mock_blob(ref) := _blobs[ref]

_mock_unpinned_blob(ref) := _unpinned_blobs[ref]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_with_related_images := _attestations_with_attachment("sha256:related_digest")

_attestations_with_attachment(attachment) := attestations if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"validate-fbc",
		[{
			"name": olm_release._related_images_result_name,
			"type": "string",
			"value": attachment,
		}],
	)

	attestations := [
		lib_test.att_mock_helper_ref(
			olm_release._related_images_result_name,
			attachment,
			"validate-fbc",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
}

test_image_ref_with_digest if {
	img := {"repo": "registry.io/repo", "digest": "sha256:abc", "tag": "latest"}
	expected := "registry.io/repo@sha256:abc"
	lib.assert_equal(olm_release._image_ref(img), expected)
}

test_image_ref_with_tag if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": "latest"}
	expected := "registry.io/repo:latest"
	lib.assert_equal(olm_release._image_ref(img), expected)
}

test_image_ref_with_repo_only if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": ""}
	expected := "registry.io/repo"
	lib.assert_equal(olm_release._image_ref(img), expected)
}
