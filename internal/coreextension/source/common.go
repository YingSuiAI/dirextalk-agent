package source

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
)

var (
	ErrMalformed    = errors.New("source response malformed")
	ErrOversize     = errors.New("source response exceeds limit")
	ErrUnauthorized = errors.New("source authorization failed")
	ErrRedirect     = errors.New("source redirect rejected")
	ErrUnsupported  = errors.New("source artifact unsupported")
)

const (
	DefaultTimeout = 15 * time.Second
	DefaultMaxBody = 8 << 20
)

const (
	OfficialRegistryAuthority = "https://registry.modelcontextprotocol.io"
	SmitheryAuthority         = "https://api.smithery.ai"
	GlamaAuthority            = "https://glama.ai"
	GitHubAuthority           = "https://api.github.com"
	SkillsShAuthority         = "https://skills.sh"
)

// HTTPConfig is intentionally injectable so adapters can be tested without a
// live network. Production callers should leave AllowHTTP false.
type HTTPConfig struct {
	BaseURL      string
	Client       *http.Client
	Timeout      time.Duration
	MaxBodyBytes int64
	BearerToken  string
	AllowHTTP    bool
	TestOnly     bool
	Resolver     Resolver
	Dialer       DialControl
}

// Resolver is injectable only for bounded tests; production uses the system
// resolver and rejects non-public results before creating network grants.
type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type DialControl interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type client struct {
	base     *url.URL
	http     *http.Client
	timeout  time.Duration
	max      int64
	token    string
	resolver Resolver
	testOnly bool
}

func newClient(cfg HTTPConfig) (*client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("base URL required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(cfg.AllowHTTP && u.Scheme == "http")) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid base URL")
	}
	hc := cfg.Client
	if hc != nil && !cfg.TestOnly {
		return nil, fmt.Errorf("custom client requires test-only mode")
	}
	if cfg.Dialer != nil && !cfg.TestOnly {
		return nil, fmt.Errorf("custom dialer requires test-only mode")
	}
	if hc == nil {
		// Provider requests enforce their destination through safeDialer. An
		// ambient process proxy would replace that destination with the proxy
		// address, either bypassing the public-IP fence or making a private
		// deployment proxy fail every provider request. Keep this security
		// boundary direct; a future managed proxy must be an explicit, validated
		// product configuration rather than inherited process state.
		t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		if !cfg.TestOnly && !cfg.AllowHTTP {
			t.DialContext = safeDialer(cfg.Resolver)
		}
		hc = &http.Client{Transport: t}
	}
	if !cfg.TestOnly && !cfg.AllowHTTP {
		if tr, ok := hc.Transport.(*http.Transport); ok {
			cp := tr.Clone()
			if cp.TLSClientConfig == nil {
				cp.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			} else if cp.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				cp.TLSClientConfig = cp.TLSClientConfig.Clone()
				cp.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
			cp.DialContext = safeDialer(cfg.Resolver)
			hc.Transport = cp
		} else if hc.Transport != nil {
			return nil, fmt.Errorf("custom transport requires test-only mode")
		}
	}
	if cfg.Dialer != nil {
		if tr, ok := hc.Transport.(*http.Transport); ok {
			cp := tr.Clone()
			cp.DialContext = cfg.Dialer.DialContext
			hc.Transport = cp
		}
	}
	// Never follow a redirect to a different host or downgrade TLS.
	baseHost := strings.ToLower(u.Host)
	baseScheme := u.Scheme
	copyClient := *hc
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || strings.ToLower(req.URL.Host) != baseHost || (baseScheme == "https" && req.URL.Scheme != "https") {
			return ErrRedirect
		}
		return nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBody
	}
	return &client{base: u, http: &copyClient, timeout: cfg.Timeout, max: cfg.MaxBodyBytes, token: cfg.BearerToken, resolver: cfg.Resolver, testOnly: cfg.TestOnly || cfg.AllowHTTP}, nil
}
func newProviderClient(cfg HTTPConfig, authority string) (*client, error) {
	if !cfg.TestOnly {
		if cfg.BaseURL == "" {
			cfg.BaseURL = authority
		}
		if cfg.BaseURL != authority {
			return nil, fmt.Errorf("provider authority mismatch")
		}
		cfg.AllowHTTP = false
	}
	return newClient(cfg)
}

func (c *client) get(ctx context.Context, p string, query url.Values) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	u := *c.base
	u.Path = path.Join(strings.TrimSuffix(c.base.Path, "/"), "/", strings.TrimPrefix(p, "/"))
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("source request failed")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return nil, ErrRedirect
		}
		return nil, fmt.Errorf("source request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("source request returned status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil {
		return nil, fmt.Errorf("source response read failed")
	}
	if int64(len(b)) > c.max {
		return nil, ErrOversize
	}
	return b, nil
}

type cursor struct {
	Source   string `json:"s"`
	Kind     string `json:"k"`
	Query    string `json:"q"`
	PageSize int    `json:"p"`
	Offset   int    `json:"o"`
	Remote   string `json:"r,omitempty"`
}

var cursorKey = func() []byte {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return b
}()

type cursorEnvelope struct {
	Payload string `json:"p"`
	MAC     string `json:"m"`
}

func encodeCursor(v cursor) string {
	b, _ := json.Marshal(v)
	payload := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.New()
	h.Write(cursorKey)
	h.Write([]byte(payload))
	mac := hex.EncodeToString(h.Sum(nil))
	out, _ := json.Marshal(cursorEnvelope{Payload: payload, MAC: mac})
	return base64.RawURLEncoding.EncodeToString(out)
}
func decodeCursor(s, source, query string) (int, error) {
	c, err := decodeCursorValue(s, source, query, "", 0)
	return c.Offset, err
}
func decodeCursorValue(s, source, query, kind string, pageSize int) (cursor, error) {
	if s == "" {
		return cursor{Source: source, Query: query, Kind: kind, PageSize: pageSize}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, ErrMalformed
	}
	var env cursorEnvelope
	if json.Unmarshal(b, &env) != nil || env.Payload == "" || len(env.MAC) != 64 {
		return cursor{}, ErrMalformed
	}
	h := sha256.New()
	h.Write(cursorKey)
	h.Write([]byte(env.Payload))
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), env.MAC) {
		return cursor{}, ErrMalformed
	}
	raw, er := base64.RawURLEncoding.DecodeString(env.Payload)
	if er != nil {
		return cursor{}, ErrMalformed
	}
	var c cursor
	if json.Unmarshal(raw, &c) != nil || c.Source != source || c.Query != query || c.Kind != kind || c.PageSize != pageSize || c.Offset < 0 || c.Offset > 1000000 || len(c.Remote) > 2048 {
		return cursor{}, ErrMalformed
	}
	return c, nil
}

func digestBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digestJSON(v any) string     { b, _ := json.Marshal(v); return digestBytes(b) }
func providerDigest(m map[string]any) string {
	if d := rawString(m, "sha256", "digest", "checksum", "artifactDigest"); validHexDigest(d) {
		return d
	}
	return digestJSON(m)
}
func validHexDigest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
func credentialRef(id string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk:credential:"+id)).String()
}

// Candidate IDs are source-native opaque identifiers; Source already provides
// the namespace (GitHub IDs, in particular, must remain exact owner/name).
func candidateID(source, id string) string { return id }
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unnamed"
	}
	return s
}
func versionOr(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "latest") {
		return fallback
	}
	return v
}

type rawFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Digest  string `json:"sha256"`
	Mode    string `json:"mode"`
	Symlink bool   `json:"symlink"`
}

// canonicalContentFile is the exact source-to-materializer wire shape. Keep
// field order aligned with execution.materialFile: JSON object key order is
// part of the content digest and the production materializer rejects any
// alternate encoding.
type canonicalContentFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func canonicalFiles(files []rawFile, max int64) ([]rawFile, []byte, error) {
	seen := map[string]bool{}
	var total int64
	for i := range files {
		p := files[i].Path
		parts := strings.Split(p, "/")
		badPart := false
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
				badPart = true
				break
			}
		}
		if p == "" || strings.TrimSpace(p) != p || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "\x00") || badPart || seen[p] || files[i].Symlink {
			return nil, nil, ErrMalformed
		}
		seen[p] = true
		files[i].Path = p
		total += int64(len(files[i].Content))
		if total > max || int64(len(files[i].Content)) > max {
			return nil, nil, ErrOversize
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	// Canonical manifest stores path and digest only; content is fetched by Fetch.
	manifest := make([]map[string]string, 0, len(files))
	for i := range files {
		d := digestBytes([]byte(files[i].Content))
		if files[i].Digest != "" && files[i].Digest != d {
			return nil, nil, ErrMalformed
		}
		files[i].Digest = d
		manifest = append(manifest, map[string]string{"path": files[i].Path, "digest": d})
	}
	b, _ := json.Marshal(manifest)
	return files, b, nil
}

func baseInspection(c core.Candidate, files []rawFile, remoteURL string, remoteCredentialRequired bool) (core.Inspection, []byte, error) {
	return baseInspectionLimit(c, files, remoteURL, remoteCredentialRequired, DefaultMaxBody)
}
func baseInspectionLimit(c core.Candidate, files []rawFile, remoteURL string, remoteCredentialRequired bool, max int64) (core.Inspection, []byte, error) {
	if err := c.Validate(); err != nil {
		return core.Inspection{}, nil, core.ErrInvalid
	}
	files, manifest, err := canonicalFiles(files, max)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	contentObj := make([]canonicalContentFile, 0, len(files))
	for _, f := range files {
		contentObj = append(contentObj, canonicalContentFile{Path: f.Path, Content: base64.RawStdEncoding.EncodeToString([]byte(f.Content))})
	}
	content, _ := json.Marshal(contentObj)
	i := core.Inspection{Candidate: c, ContentDigest: digestBytes(content), ManifestDigest: digestBytes(manifest), ExecutionDigest: "", NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]"))}
	if remoteURL != "" {
		u, e := url.Parse(remoteURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(remoteURL, "{}") {
			return core.Inspection{}, nil, ErrUnsupported
		}
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		port := uint32(443)
		if u.Port() != "" {
			var n int
			fmt.Sscan(u.Port(), &n)
			port = uint32(n)
		}
		endpoint := &core.RemoteEndpoint{URL: u.String()}
		i.NetworkGrants = []core.NetworkGrant{{Scheme: u.Scheme, Host: u.Hostname(), Port: port, PathPrefix: p, Digest: digestBytes([]byte(u.Scheme + "://" + u.Hostname() + p))}}
		if remoteCredentialRequired {
			ref := credentialRef(c.ID)
			endpoint.CredentialReferenceID = ref
			i.SecretGrants = []core.SecretGrantDescriptor{{ReferenceID: ref, Purpose: core.SecretPurposeMCPCredential, BindingDigest: digestBytes([]byte("credential:" + ref)), Configured: false}}
		}
		i.Execution = core.ExecutionDescriptor{Remote: endpoint}
	} else if c.Kind == core.KindSkill {
		var skill rawFile
		found := false
		for _, f := range files {
			if strings.EqualFold(path.Base(f.Path), "SKILL.md") {
				skill = f
				found = true
				break
			}
		}
		if !found {
			return core.Inspection{}, nil, ErrUnsupported
		}
		i.Execution = core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: skill.Path, Digest: skill.Digest}}
	} else {
		var executable *rawFile
		for idx := range files {
			if files[idx].Path == "entry" {
				executable = &files[idx]
				break
			}
		}
		if executable == nil {
			return core.Inspection{}, nil, ErrUnsupported
		}
		entry := core.StaticEntry{RelativePath: "entry", Digest: executable.Digest, Argv: []string{"entry"}}
		i.Execution = core.ExecutionDescriptor{Stdio: &entry}
	}
	i.ExecutionDigest = digestJSON(i.Execution)
	if err := i.Validate(); err != nil {
		return core.Inspection{}, nil, err
	}
	return i, content, nil
}

func rawString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
func rawExactString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok {
			return v
		}
	}
	return ""
}
func rawMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func rawSlice(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func parseJSON(b []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		return ErrMalformed
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

var hex40 = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func fullCommit(s string) bool { return hex40.MatchString(strings.TrimSpace(s)) }

func (c *client) validateRemote(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "{}") {
		return ErrUnsupported
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return ErrUnsupported
		}
		return nil
	}
	if c.testOnly {
		return nil
	}
	r := c.resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ErrUnsupported
	}
	for _, a := range ips {
		if !isPublicIP(a.IP) {
			return ErrUnsupported
		}
	}
	return nil
}
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 10 || ip4[0] == 127 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 169 && ip4[1] == 254) {
			return false
		}
	}
	return true
}
func safeDialer(r Resolver) func(context.Context, string, string) (net.Conn, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, ErrUnsupported
		}
		for _, a := range ips {
			if !isPublicIP(a.IP) {
				continue
			}
			conn, e := d.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, ErrUnsupported
	}
}
