package secret

import "time"

// Secret represents a bundle of key-value pairs with metadata.
type Secret struct {
	Name     string            `json:"name"`
	Tags     map[string]string `json:"tags"`
	Values   map[string]string `json:"values"`
	Lockable bool              `json:"lockable,omitempty"`
	Created  time.Time         `json:"created"`
	Modified time.Time         `json:"modified"`
}

// New creates a new Secret with the given name.
func New(name string) *Secret {
	now := time.Now().UTC()
	return &Secret{
		Name:     name,
		Tags:     make(map[string]string),
		Values:   make(map[string]string),
		Created:  now,
		Modified: now,
	}
}

// Get retrieves a value by key.
func (s *Secret) Get(key string) (string, bool) {
	v, ok := s.Values[key]
	return v, ok
}

// Set sets a key-value pair and updates the modified timestamp.
func (s *Secret) Set(key, value string) {
	s.Values[key] = value
	s.Modified = time.Now().UTC()
}

// Delete removes a key and updates the modified timestamp.
func (s *Secret) Delete(key string) {
	delete(s.Values, key)
	s.Modified = time.Now().UTC()
}

// SetTag sets a tag category:value pair.
func (s *Secret) SetTag(category, value string) {
	s.Tags[category] = value
	s.Modified = time.Now().UTC()
}

// RemoveTag removes a tag by category.
func (s *Secret) RemoveTag(category string) {
	delete(s.Tags, category)
	s.Modified = time.Now().UTC()
}

// HasTag checks if a tag matches category:value.
func (s *Secret) HasTag(category, value string) bool {
	v, ok := s.Tags[category]
	return ok && v == value
}
