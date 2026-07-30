package lib.oci_test

import rego.v1

import data.lib.oci

test_blob_from_image if {
	ref := "registry.io/repository/image:some-tag"
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:abc123",
		"size": 42,
	}]}

	result := oci.blob_from_image(ref) with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob

	result == "blob content"
}

test_blob_from_image_with_digest_ref if {
	ref := "registry.io/repository/image@sha256:def456"
	manifest := {"layers": [{
		"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
		"digest": "sha256:abc123",
		"size": 42,
	}]}

	result := oci.blob_from_image(ref) with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob

	result == "blob content"
}

test_blob_from_image_empty_layers if {
	manifest := {"layers": []}

	not oci.blob_from_image("registry.io/repository/image:tag") with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob
}

# Verify the helper selects the first layer, not an arbitrary one.
test_blob_from_image_multi_layer if {
	manifest := {"layers": [
		{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": "sha256:first",
			"size": 10,
		},
		{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": "sha256:second",
			"size": 20,
		},
	]}

	result := oci.blob_from_image("registry.io/repo/img:tag") with ec.oci.image_manifest as manifest
		with ec.oci.blob as _mock_blob_multi

	result == "first blob"
}

test_parsed_blob_if_valid_json if {
	result := oci.parsed_blob_if_valid("ref") with ec.oci.blob as _mock_json_blob
	result == {"key": "value"}
}

test_parsed_blob_if_valid_invalid_json if {
	not oci.parsed_blob_if_valid("ref") with ec.oci.blob as _mock_invalid_blob
}

test_parsed_blob_if_valid_null if {
	not oci.parsed_blob_if_valid("ref") with ec.oci.blob as null
}

# Mock that only returns a value for the expected digest ref, verifying
# that blob_from_image constructs the correct ref from the layer digest.
_mock_blob("registry.io/repository/image@sha256:abc123") := "blob content"

_mock_blob_multi("registry.io/repo/img@sha256:first") := "first blob"

_mock_json_blob(_) := `{"key": "value"}`

_mock_invalid_blob(_) := "not valid json {"

# --- Tests for verified_image_referrers ---

test_verified_image_referrers_success if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	result := oci.verified_image_referrers(ref, identity) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(result) == 1
}

test_verified_image_referrers_verification_fails if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	result := oci.verified_image_referrers(ref, identity) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 0
}

test_verified_image_referrers_invalid_identity if {
	ref := "registry.io/repo/img@sha256:abc123"
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]

	# An identity that is not a usable verification config causes fail-closed:
	# no referrers returned even though the verify_image mock would succeed.
	# Empty object (fails sigstore.validate) and non-object both fail-closed.
	empty_result := oci.verified_image_referrers(ref, {}) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(empty_result) == 0

	non_object_result := oci.verified_image_referrers(ref, "not-an-object") with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(non_object_result) == 0
}

# --- Tests for verified_image_tag_refs ---

test_verified_image_tag_refs_success if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.verified_image_tag_refs(ref, identity) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(result) == 1
}

test_verified_image_tag_refs_verification_fails if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.verified_image_tag_refs(ref, identity) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 0
}

test_verified_image_tag_refs_invalid_identity if {
	ref := "registry.io/repo/img@sha256:abc123"
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.verified_image_tag_refs(ref, {}) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(result) == 0
}

# --- Tests for image_referrer_failures ---

test_image_referrer_failures_on_error if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	result := oci.image_referrer_failures(ref, identity) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 1
	some failure in result
	failure.errors == ["verification failed"]
}

test_image_referrer_failures_empty_on_success if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	result := oci.image_referrer_failures(ref, identity) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(result) == 0
}

test_image_referrer_failures_empty_invalid_identity if {
	ref := "registry.io/repo/img@sha256:abc123"
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repo/img@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	result := oci.image_referrer_failures(ref, {}) with ec.oci.image_referrers as mock_referrers
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 0
}

# --- Tests for image_tag_ref_failures ---

test_image_tag_ref_failures_on_error if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.image_tag_ref_failures(ref, identity) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 1
	some failure in result
	failure.errors == ["verification failed"]
}

test_image_tag_ref_failures_empty_on_success if {
	ref := "registry.io/repo/img@sha256:abc123"
	identity := {"public_key": "my-signing-key", "ignore_rekor": true}
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.image_tag_ref_failures(ref, identity) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_success
	count(result) == 0
}

test_image_tag_ref_failures_empty_invalid_identity if {
	ref := "registry.io/repo/img@sha256:abc123"
	mock_tag_refs := ["registry.io/repo/img:sha256-abc123.sbom"]
	result := oci.image_tag_ref_failures(ref, {}) with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_failure
	count(result) == 0
}

_mock_verify_image_success(_, _) := {"errors": []}

_mock_verify_image_failure(_, _) := {"errors": ["verification failed"]}
