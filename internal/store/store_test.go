package store

import (
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "veil.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestInviteSingleUse(t *testing.T) {
	s := open(t)
	if err := s.CreateInvite("abc-123"); err != nil {
		t.Fatal(err)
	}
	ok, err := s.ConsumeInvite("abc-123")
	if err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}
	ok, _ = s.ConsumeInvite("abc-123")
	if ok {
		t.Fatal("invite consumed twice")
	}
	ok, _ = s.ConsumeInvite("never-existed")
	if ok {
		t.Fatal("consumed a nonexistent invite")
	}
}

func TestDeviceLifecycle(t *testing.T) {
	s := open(t)
	const pub = "BASE64KEY=="
	if has, _ := s.HasDevice(pub); has {
		t.Fatal("unexpected device before enroll")
	}
	if err := s.AddDevice(pub, "laptop"); err != nil {
		t.Fatal(err)
	}
	if has, _ := s.HasDevice(pub); !has {
		t.Fatal("device missing after enroll")
	}
	devs, _ := s.ListDevices()
	if len(devs) != 1 || devs[0].Name != "laptop" {
		t.Fatalf("unexpected device list: %+v", devs)
	}
	ok, _ := s.RevokeDevice(pub)
	if !ok {
		t.Fatal("revoke reported not found")
	}
	if has, _ := s.HasDevice(pub); has {
		t.Fatal("device still present after revoke")
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "veil.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.AddDevice("k1", "a")
	s1.CreateInvite("inv1")
	s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if has, _ := s2.HasDevice("k1"); !has {
		t.Fatal("device did not persist")
	}
	invs, _ := s2.ListInvites()
	if len(invs) != 1 || invs[0] != "inv1" {
		t.Fatalf("invites did not persist: %v", invs)
	}
}
