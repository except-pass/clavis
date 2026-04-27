package tags

import (
	"errors"
	"sort"
	"strings"
)

var (
	ErrInvalidFormat = errors.New("invalid tag format, expected category:value")
	ErrEmptyCategory = errors.New("tag category cannot be empty")
	ErrEmptyValue    = errors.New("tag value cannot be empty")
)

// SuggestedCategories are the recommended tag categories.
var SuggestedCategories = []string{"env", "service", "type"}

// categoryOrder defines the canonical ordering for tag categories.
var categoryOrder = map[string]int{
	"env":     0,
	"service": 1,
	"type":    2,
}

// Parse parses a tag string in "category:value" format.
func Parse(s string) (category, value string, err error) {
	if s == "" {
		return "", "", ErrInvalidFormat
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", ErrInvalidFormat
	}
	category = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	if category == "" {
		return "", "", ErrEmptyCategory
	}
	if value == "" {
		return "", "", ErrEmptyValue
	}
	return category, value, nil
}

// IsSuggestedCategory returns true if the category is in the suggested list.
func IsSuggestedCategory(category string) bool {
	for _, c := range SuggestedCategories {
		if c == category {
			return true
		}
	}
	return false
}

// CanonicalOrder returns tag categories sorted by canonical order.
// Suggested categories come first (env, service, type), then alphabetical.
func CanonicalOrder(tags map[string]string) []string {
	categories := make([]string, 0, len(tags))
	for cat := range tags {
		categories = append(categories, cat)
	}

	sort.Slice(categories, func(i, j int) bool {
		orderI, knownI := categoryOrder[categories[i]]
		orderJ, knownJ := categoryOrder[categories[j]]

		if knownI && knownJ {
			return orderI < orderJ
		}
		if knownI {
			return true
		}
		if knownJ {
			return false
		}
		return categories[i] < categories[j]
	})

	return categories
}

// DeriveName generates a secret name from tags in canonical order.
func DeriveName(tags map[string]string) string {
	order := CanonicalOrder(tags)
	parts := make([]string, 0, len(order))
	for _, cat := range order {
		parts = append(parts, tags[cat])
	}
	return strings.Join(parts, "/")
}
