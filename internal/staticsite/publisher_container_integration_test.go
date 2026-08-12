package staticsite

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

func TestPublisherServesImmutableHTMLThroughHardenedCaddyOptIn(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("AGENT_TEST_CADDY_IMAGE"))
	if image == "" {
		t.Skip("set AGENT_TEST_CADDY_IMAGE to an immutable caddy@sha256 image")
	}
	if !strings.Contains(image, "@sha256:") {
		t.Fatal("AGENT_TEST_CADDY_IMAGE must be immutable")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is unavailable")
	}
	root := t.TempDir()
	publisher, err := NewPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	publication := core.StaticSitePublication{
		SiteID: uuid.NewString(), ReleaseID: uuid.NewString(),
		HTML: []byte("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Dirextalk</title><style>body{font-family:sans-serif}</style><main><h1>本地静态站点验收</h1></main></html>"),
	}
	receipt, err := publisher.PublishSingleHTML(context.Background(), publication)
	if err != nil {
		t.Fatal(err)
	}
	caddyfile := filepath.Join(root, "Caddyfile")
	config := `:8080 {
handle_path /.sites/* {
  root * /srv/dirextalk-sites
  header {
    Content-Security-Policy "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; media-src data:; script-src 'none'; connect-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
    Referrer-Policy "no-referrer"
    Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    Cross-Origin-Resource-Policy "same-origin"
    Cache-Control "public, max-age=31536000, immutable"
  }
  file_server
}
respond /backend-probe "backend" 200
}
`
	if err = os.WriteFile(caddyfile, []byte(config), 0o444); err != nil {
		t.Fatal(err)
	}
	name := "dirextalk-static-site-test-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	cleanup := func() { _ = exec.Command("docker", "rm", "-f", name).Run() }
	t.Cleanup(cleanup)
	args := []string{
		"run", "--detach", "--name", name, "--network", "bridge", "--read-only",
		"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777", "--tmpfs", "/data", "--tmpfs", "/config",
		"--publish", "127.0.0.1::8080",
		"--mount", "type=bind,src=" + filepath.Join(root, "public") + ",dst=/srv/dirextalk-sites,readonly",
		"--mount", "type=bind,src=" + caddyfile + ",dst=/etc/caddy/Caddyfile,readonly",
		image, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile",
	}
	if output, runErr := exec.Command("docker", args...).CombinedOutput(); runErr != nil {
		t.Fatalf("start caddy: %v: %s", runErr, output)
	}
	portRaw, err := exec.Command("docker", "port", name, "8080/tcp").Output()
	if err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("inspect Caddy port: %v: %s", err, logs)
	}
	address := strings.TrimSpace(string(portRaw))
	if !strings.HasPrefix(address, "127.0.0.1:") {
		t.Fatalf("unexpected published address %q", address)
	}
	baseURL := "http://" + address
	client := &http.Client{Timeout: 2 * time.Second}
	var response *http.Response
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err = client.Get(baseURL + receipt.PublicPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read static site: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != string(publication.HTML) {
		t.Fatalf("status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	if csp := response.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "script-src 'none'") || !strings.Contains(csp, "connect-src 'none'") || !strings.Contains(csp, "form-action 'none'") {
		t.Fatalf("CSP=%q", csp)
	}
	if response.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers=%v", response.Header)
	}
	missing, err := client.Get(baseURL + "/.sites/" + publication.SiteID + "/" + uuid.NewString() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status=%d", missing.StatusCode)
	}
	backend, err := client.Get(baseURL + "/backend-probe")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Body.Close()
	if backend.StatusCode != http.StatusOK {
		t.Fatalf("backend probe status=%d", backend.StatusCode)
	}
	inspect, err := exec.Command("docker", "inspect", "--format", `{{range .Mounts}}{{if eq .Destination "/srv/dirextalk-sites"}}{{printf "%v" .RW}}{{end}}{{end}}`, name).Output()
	if err != nil || strings.TrimSpace(string(inspect)) != "false" {
		t.Fatalf("static mount is not read-only: %q err=%v", inspect, err)
	}
	if logs, logErr := exec.Command("docker", "logs", name).CombinedOutput(); logErr != nil {
		t.Fatalf("caddy logs unavailable: %v: %s", logErr, logs)
	} else if strings.Contains(strings.ToLower(string(logs)), "error") {
		t.Fatalf("caddy logged an error: %s", logs)
	}
	t.Logf("served %s through %s", receipt.PublicPath, fmt.Sprintf("%s@%s", image, address))
}
