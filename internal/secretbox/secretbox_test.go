package secretbox

import (
	"bytes"
	"testing"
)

func TestKeyFileRoundTrip(t *testing.T) {
	const pass = "correct horse battery staple"
	if _, err := NewKeyFile("short"); err == nil {
		t.Error("short passphrase accepted")
	}
	kf, err := NewKeyFile(pass)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(kf, []byte(pass)) {
		t.Fatal("passphrase in key file")
	}
	box, err := Load(kf, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(kf, pass+"x"); err == nil {
		t.Error("wrong passphrase accepted")
	}
	again, _ := Load(kf, pass)
	if box.KeyID() == "" || box.KeyID() != again.KeyID() {
		t.Errorf("key id %q vs %q", box.KeyID(), again.KeyID())
	}
	other, _ := NewKeyFile(pass)
	ob, _ := Load(other, pass)
	if ob.KeyID() == box.KeyID() {
		t.Error("two generated keys share an id")
	}

	sealed, err := box.Seal([]byte("K7QX9MBR4T"), []byte("agent-1|100"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("K7QX9MBR4T")) {
		t.Fatal("plaintext visible")
	}
	got, err := again.Open(sealed, []byte("agent-1|100"))
	if err != nil || string(got) != "K7QX9MBR4T" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := box.Open(sealed, []byte("agent-2|100")); err == nil {
		t.Error("opened under a different binding")
	}
	if _, err := ob.Open(sealed, []byte("agent-1|100")); err == nil {
		t.Error("opened with a different key")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := box.Open(sealed, []byte("agent-1|100")); err == nil {
		t.Error("tampered value opened")
	}
	if _, err := box.Open([]byte{1, 2}, nil); err == nil {
		t.Error("short value opened")
	}
}
