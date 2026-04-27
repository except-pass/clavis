package tags

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input    string
		category string
		value    string
		wantErr  bool
	}{
		{"env:prod", "env", "prod", false},
		{"service:influx", "service", "influx", false},
		{"type:database", "type", "database", false},
		{"custom:value", "custom", "value", false},
		{"invalid", "", "", true},
		{"", "", "", true},
		{":value", "", "", true},
		{"category:", "", "", true},
	}

	for _, tt := range tests {
		cat, val, err := Parse(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if cat != tt.category || val != tt.value {
			t.Errorf("Parse(%q) = (%q, %q), want (%q, %q)", tt.input, cat, val, tt.category, tt.value)
		}
	}
}

func TestIsSuggestedCategory(t *testing.T) {
	if !IsSuggestedCategory("env") {
		t.Error("env should be a suggested category")
	}
	if !IsSuggestedCategory("service") {
		t.Error("service should be a suggested category")
	}
	if !IsSuggestedCategory("type") {
		t.Error("type should be a suggested category")
	}
	if IsSuggestedCategory("custom") {
		t.Error("custom should not be a suggested category")
	}
}

func TestCanonicalOrder(t *testing.T) {
	tags := map[string]string{
		"type":    "database",
		"service": "influx",
		"env":     "prod",
		"custom":  "value",
	}

	ordered := CanonicalOrder(tags)
	expected := []string{"env", "service", "type", "custom"}

	if !reflect.DeepEqual(ordered, expected) {
		t.Errorf("CanonicalOrder = %v, want %v", ordered, expected)
	}
}

func TestDeriveName(t *testing.T) {
	tags := map[string]string{
		"env":     "prod",
		"service": "influx",
	}
	name := DeriveName(tags)
	if name != "prod/influx" {
		t.Errorf("DeriveName = %q, want %q", name, "prod/influx")
	}

	tags2 := map[string]string{
		"service": "mysql",
		"env":     "dev",
		"type":    "database",
	}
	name2 := DeriveName(tags2)
	if name2 != "dev/mysql/database" {
		t.Errorf("DeriveName = %q, want %q", name2, "dev/mysql/database")
	}
}
