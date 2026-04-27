package format

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/except-pass/clavis/internal/secret"
)

func newTestSecret() *secret.Secret {
	s := secret.New("prod/influx")
	s.Set("username", "admin")
	s.Set("password", "secret123")
	s.SetTag("env", "prod")
	return s
}

func TestEnvFormatter(t *testing.T) {
	s := newTestSecret()
	f := &EnvFormatter{}

	output, err := f.Format(s, "")
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "export PROD_INFLUX_USERNAME='admin'") {
		t.Errorf("missing username export in: %s", output)
	}
	if !strings.Contains(output, "export PROD_INFLUX_PASSWORD='secret123'") {
		t.Errorf("missing password export in: %s", output)
	}
}

func TestJSONFormatter(t *testing.T) {
	s := newTestSecret()
	f := &JSONFormatter{}

	output, err := f.Format(s, "")
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, `"username": "admin"`) {
		t.Errorf("missing username in: %s", output)
	}
}

func TestYAMLFormatter(t *testing.T) {
	s := newTestSecret()
	f := &YAMLFormatter{}

	output, err := f.Format(s, "")
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "username: admin") {
		t.Errorf("missing username in: %s", output)
	}
}

func TestDockerFormatter(t *testing.T) {
	s := newTestSecret()
	f := &DockerFormatter{}

	output, err := f.Format(s, "")
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "PROD_INFLUX_USERNAME=admin") {
		t.Errorf("missing username in: %s", output)
	}
	if strings.Contains(output, "export") {
		t.Errorf("docker format should not have export: %s", output)
	}
}

func TestFilesFormatter(t *testing.T) {
	s := newTestSecret()
	f := &FilesFormatter{}

	dir := t.TempDir()
	output, err := f.Format(s, dir)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(output, "Wrote 2 files") {
		t.Errorf("unexpected output: %s", output)
	}

	// Check files were created
	userFile := filepath.Join(dir, "PROD_INFLUX_USERNAME")
	data, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatalf("reading username file: %v", err)
	}
	if string(data) != "admin" {
		t.Errorf("username file = %q, want admin", data)
	}

	// Check permissions
	info, _ := os.Stat(userFile)
	if info.Mode().Perm() != 0600 {
		t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestGetFormatter(t *testing.T) {
	f, err := Get("env")
	if err != nil {
		t.Fatalf("Get(env) failed: %v", err)
	}
	if _, ok := f.(*EnvFormatter); !ok {
		t.Error("expected EnvFormatter")
	}

	f, err = Get("json")
	if err != nil {
		t.Fatalf("Get(json) failed: %v", err)
	}
	if _, ok := f.(*JSONFormatter); !ok {
		t.Error("expected JSONFormatter")
	}
}
