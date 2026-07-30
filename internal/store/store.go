// Package store is the server's embedded, dependency-free persistence layer
// (bbolt): it holds enrollment invites and the set of enrolled device public
// keys. No external database is needed to self-host.
package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketInvites = []byte("invites")
	bucketDevices = []byte("devices")
)

// Device is an enrolled client device.
type Device struct {
	PublicKey  string    `json:"public_key"` // base64 X25519 static key
	Name       string    `json:"name"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// Store wraps a bbolt database.
type Store struct{ db *bolt.DB }

// Open opens (creating if needed) the store at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketInvites, bucketDevices} {
			if _, e := tx.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CreateInvite records a single-use enrollment invite code.
func (s *Store) CreateInvite(code string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketInvites).Put([]byte(code), []byte(time.Now().UTC().Format(time.RFC3339)))
	})
}

// ConsumeInvite atomically deletes the invite if present, reporting whether it
// existed. Invites are single-use.
func (s *Store) ConsumeInvite(code string) (bool, error) {
	var ok bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketInvites)
		if b.Get([]byte(code)) == nil {
			return nil
		}
		ok = true
		return b.Delete([]byte(code))
	})
	return ok, err
}

// ListInvites returns all outstanding invite codes.
func (s *Store) ListInvites() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketInvites).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// AddDevice records an enrolled device by its base64 public key.
func (s *Store) AddDevice(pubKey, name string) error {
	buf, err := json.Marshal(Device{PublicKey: pubKey, Name: name, EnrolledAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).Put([]byte(pubKey), buf)
	})
}

// HasDevice reports whether a device with the given base64 public key is enrolled.
func (s *Store) HasDevice(pubKey string) (bool, error) {
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		ok = tx.Bucket(bucketDevices).Get([]byte(pubKey)) != nil
		return nil
	})
	return ok, err
}

// ListDevices returns all enrolled devices.
func (s *Store) ListDevices() ([]Device, error) {
	var out []Device
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(_, v []byte) error {
			var d Device
			if e := json.Unmarshal(v, &d); e != nil {
				return e
			}
			out = append(out, d)
			return nil
		})
	})
	return out, err
}

// RevokeDevice removes a device, reporting whether it existed.
func (s *Store) RevokeDevice(pubKey string) (bool, error) {
	var ok bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDevices)
		if b.Get([]byte(pubKey)) == nil {
			return nil
		}
		ok = true
		return b.Delete([]byte(pubKey))
	})
	return ok, err
}
