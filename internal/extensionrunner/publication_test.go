package extensionrunner

import "testing"

func TestPublishProtocolCanonicalAndTamperBound(t *testing.T) {
	e := ManifestEntry{Path: "entry", SHA256: DigestBytes([]byte("x")), Size: 1}
	r := PublishRequest{Op: "publish_v1", Entries: []ManifestEntry{e}}
	r.Digest = ManifestDigest(r.Entries)
	b, err := EncodePublishRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePublishRequest(b)
	if err != nil || got.Digest != r.Digest {
		t.Fatalf("decode=%#v err=%v", got, err)
	}
	if _, err = DecodePublishRequest(append(b, ' ')); err == nil {
		t.Fatal("noncanonical publish accepted")
	}
	r.Entries[0].SHA256 = DigestBytes([]byte("tampered"))
	if err = ValidatePublishRequest(r, 1); err == nil {
		t.Fatal("tampered digest accepted")
	}
	if err = ValidatePublishRequest(PublishRequest{Op: "publish_v1", Digest: r.Digest, Entries: []ManifestEntry{e}}, 0); err == nil {
		t.Fatal("fd count mismatch accepted")
	}
	badPath := PublishRequest{Op: "publish_v1", Entries: []ManifestEntry{{Path: "../entry", SHA256: e.SHA256, Size: 1}}}
	badPath.Digest = ManifestDigest(badPath.Entries)
	if err = ValidatePublishRequest(badPath, 1); err == nil {
		t.Fatal("traversal path accepted")
	}
}
