package secret

import (
	"testing"
	"time"
)

func TestNewSecret(t *testing.T) {
	s := New("prod/influx")
	if s.Name != "prod/influx" {
		t.Errorf("expected name prod/influx, got %s", s.Name)
	}
	if s.Tags == nil {
		t.Error("expected tags to be initialized")
	}
	if s.Values == nil {
		t.Error("expected values to be initialized")
	}
	if s.Created.IsZero() {
		t.Error("expected created timestamp to be set")
	}
}

func TestSecretSetGet(t *testing.T) {
	s := New("test")
	s.Set("username", "admin")
	s.Set("password", "secret")

	if v, ok := s.Get("username"); !ok || v != "admin" {
		t.Errorf("expected username=admin, got %s", v)
	}
	if v, ok := s.Get("password"); !ok || v != "secret" {
		t.Errorf("expected password=secret, got %s", v)
	}
	if _, ok := s.Get("nonexistent"); ok {
		t.Error("expected nonexistent key to return false")
	}
}

func TestSecretDelete(t *testing.T) {
	s := New("test")
	s.Set("key", "value")
	s.Delete("key")

	if _, ok := s.Get("key"); ok {
		t.Error("expected key to be deleted")
	}
}

func TestSecretModifiedTimestamp(t *testing.T) {
	s := New("test")
	original := s.Modified

	time.Sleep(1 * time.Millisecond)
	s.Set("key", "value")

	if !s.Modified.After(original) {
		t.Error("expected modified timestamp to be updated")
	}
}

func TestSecretLockableField(t *testing.T) {
	s := New("test")

	// Default should be false
	if s.Lockable {
		t.Error("expected Lockable to default to false")
	}

	// Set to true
	s.Lockable = true
	if !s.Lockable {
		t.Error("expected Lockable to be true after setting")
	}

	// Toggle back to false
	s.Lockable = false
	if s.Lockable {
		t.Error("expected Lockable to be false after unsetting")
	}
}
