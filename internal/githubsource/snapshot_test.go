package githubsource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestSnapshotterUsesReadTokenWithoutForwardingItToCodeload(
	t *testing.T,
) {
	t.Parallel()
	fixture := newSnapshotTestFixture(t)
	archive := sourceGzip(t, []sourceMember{
		sourceDirectory("source-root/", 0o700, time.Unix(90, 0)),
		sourceDirectory("source-root/src/", 0o777, time.Unix(80, 0)),
		sourceRegular(
			"source-root/src/main.go",
			0o666,
			[]byte("package main\n"),
			time.Unix(70, 0),
		),
		sourceRegular(
			"source-root/run.sh",
			0o777,
			[]byte("#!/bin/sh\n"),
			time.Unix(60, 0),
		),
		sourceSymlink(
			"source-root/current.go",
			"src/main.go",
			time.Unix(50, 0),
		),
	})
	archiveCalls := 0
	archiveTransport := sourceRoundTripFunc(func(
		request *http.Request,
	) (*http.Response, error) {
		archiveCalls++
		switch archiveCalls {
		case 1:
			expected := "https://api.github.com/repos/" +
				fixture.binding.Repository.Owner + "/" +
				fixture.binding.Repository.Name + "/tarball/" +
				fixture.binding.Repository.BaseCommitSHA
			if request.Method != http.MethodGet ||
				request.URL.String() != expected ||
				request.Header.Get("Authorization") !=
					"Bearer "+fixture.token ||
				request.Header.Get("X-GitHub-Api-Version") !=
					"2026-03-10" {
				t.Fatalf("unexpected archive request: %#v", request)
			}
			return sourceResponse(
				http.StatusFound,
				nil,
				map[string]string{
					"Location": "https://codeload.github.com/" +
						fixture.binding.Repository.Owner + "/" +
						fixture.binding.Repository.Name +
						"/legacy.tar.gz/" +
						fixture.binding.Repository.BaseCommitSHA,
				},
			), nil
		case 2:
			if request.Method != http.MethodGet ||
				request.URL.Host != "codeload.github.com" ||
				request.Header.Get("Authorization") != "" ||
				request.Header.Get("X-GitHub-Api-Version") != "" {
				t.Fatalf(
					"credential leaked to codeload: %#v",
					request.Header,
				)
			}
			return sourceResponse(
				http.StatusOK,
				archive,
				nil,
			), nil
		default:
			t.Fatalf("unexpected archive call %d", archiveCalls)
			return nil, nil
		}
	})
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotter, err := NewSnapshotter(
		fixture.broker,
		archiveTransport,
		root,
	)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := snapshotter.Prepare(
		context.Background(),
		fixture.binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := prepared.directory
	defer prepared.Destroy()
	if archiveCalls != 2 ||
		fixture.tokenRequests != 1 ||
		prepared.Snapshot.Validate() != nil ||
		prepared.Snapshot.InputID != fixture.binding.InputID ||
		prepared.Snapshot.InputDigest != fixture.binding.InputDigest ||
		prepared.Snapshot.SourceDigest != fixture.binding.SourceDigest ||
		prepared.Snapshot.Repository != fixture.binding.Repository ||
		prepared.Snapshot.FileCount != 4 {
		t.Fatalf(
			"snapshot facts drifted: calls=%d token_requests=%d snapshot=%#v",
			archiveCalls,
			fixture.tokenRequests,
			prepared.Snapshot,
		)
	}
	canonical := readPrepared(t, &prepared)
	digest := sha256.Sum256(canonical)
	if prepared.Snapshot.WorkspaceDigest !=
		"sha256:"+hex.EncodeToString(digest[:]) ||
		prepared.Snapshot.SizeBytes != int64(len(canonical)) {
		t.Fatalf("workspace digest or size drifted: %#v", prepared.Snapshot)
	}
	assertCanonicalWorkspace(t, canonical)
	prepared.Destroy()
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepared directory survived destroy: %v", err)
	}
	if _, err := prepared.Open(
		context.Background(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("destroyed snapshot remained openable: %v", err)
	}
}

func TestSnapshotCanonicalizationIsDeterministic(t *testing.T) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	firstArchive := sourceGzip(t, []sourceMember{
		sourceDirectory("first-root/", 0o700, time.Unix(100, 0)),
		sourceDirectory("first-root/src/", 0o700, time.Unix(101, 0)),
		sourceRegular(
			"first-root/src/main.go",
			0o600,
			[]byte("package main\n"),
			time.Unix(102, 0),
		),
		sourceRegular(
			"first-root/run.sh",
			0o700,
			[]byte("#!/bin/sh\n"),
			time.Unix(103, 0),
		),
		sourceSymlink(
			"first-root/current.go",
			"src/main.go",
			time.Unix(104, 0),
		),
	})
	secondArchive := sourceGzip(t, []sourceMember{
		sourceDirectory("different-root/", 0o755, time.Unix(900, 0)),
		sourceSymlink(
			"different-root/current.go",
			"src/main.go",
			time.Unix(904, 0),
		),
		sourceRegular(
			"different-root/run.sh",
			0o777,
			[]byte("#!/bin/sh\n"),
			time.Unix(903, 0),
		),
		sourceRegular(
			"different-root/src/main.go",
			0o664,
			[]byte("package main\n"),
			time.Unix(902, 0),
		),
		sourceDirectory(
			"different-root/src/",
			0o777,
			time.Unix(901, 0),
		),
	})
	snapshotter := &Snapshotter{tempRoot: t.TempDir()}
	first, err := snapshotter.canonicalize(
		context.Background(),
		binding,
		bytes.NewReader(firstArchive),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := snapshotter.canonicalize(
		context.Background(),
		binding,
		bytes.NewReader(secondArchive),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	firstBytes := readPrepared(t, &first)
	secondBytes := readPrepared(t, &second)
	if !bytes.Equal(firstBytes, secondBytes) ||
		first.Snapshot != second.Snapshot {
		t.Fatalf(
			"canonical snapshot drifted: first=%#v second=%#v",
			first.Snapshot,
			second.Snapshot,
		)
	}
}

func TestSnapshotCanonicalizationRejectsUnsafeArchives(t *testing.T) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	tests := []struct {
		name    string
		members []sourceMember
	}{
		{
			name: "path traversal",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"root/../escape",
					0o600,
					[]byte("x"),
					time.Time{},
				),
			},
		},
		{
			name: "absolute path",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"/root/escape",
					0o600,
					[]byte("x"),
					time.Time{},
				),
			},
		},
		{
			name: "mixed roots",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"other/file",
					0o600,
					[]byte("x"),
					time.Time{},
				),
			},
		},
		{
			name: "escaping symlink",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceSymlink(
					"root/nested/link",
					"../../outside",
					time.Time{},
				),
			},
		},
		{
			name: "hard link",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				{header: tar.Header{
					Name:     "root/link",
					Typeflag: tar.TypeLink,
					Linkname: "root/target",
				}},
			},
		},
		{
			name: "device",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				{header: tar.Header{
					Name:     "root/device",
					Typeflag: tar.TypeChar,
				}},
			},
		},
		{
			name: "duplicate",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"root/file",
					0o600,
					[]byte("a"),
					time.Time{},
				),
				sourceRegular(
					"root/file",
					0o600,
					[]byte("b"),
					time.Time{},
				),
			},
		},
		{
			name: "reserved marker",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"root/"+workerruntime.WorkspaceDigestMarker,
					0o600,
					[]byte("forged"),
					time.Time{},
				),
			},
		},
		{
			name: "symlink parent",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceSymlink(
					"root/vendor",
					"src",
					time.Time{},
				),
				sourceRegular(
					"root/vendor/file",
					0o600,
					[]byte("x"),
					time.Time{},
				),
			},
		},
		{
			name: "regular parent",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
				sourceRegular(
					"root/parent",
					0o600,
					[]byte("x"),
					time.Time{},
				),
				sourceRegular(
					"root/parent/child",
					0o600,
					[]byte("x"),
					time.Time{},
				),
			},
		},
		{
			name: "empty repository",
			members: []sourceMember{
				sourceDirectory("root/", 0o755, time.Time{}),
			},
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			snapshotter := &Snapshotter{tempRoot: root}
			archive := sourceGzip(t, testCase.members)
			prepared, err := snapshotter.canonicalize(
				context.Background(),
				binding,
				bytes.NewReader(archive),
			)
			prepared.Destroy()
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("unsafe archive error=%v", err)
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("unsafe archive left temporary data: %+v", entries)
			}
		})
	}
}

func TestSnapshotCanonicalizationRejectsTrailingOrConcatenatedData(
	t *testing.T,
) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	valid := sourceGzip(t, []sourceMember{
		sourceDirectory("root/", 0o755, time.Time{}),
		sourceRegular(
			"root/file",
			0o600,
			[]byte("x"),
			time.Time{},
		),
	})
	secondStream := sourceGzip(t, []sourceMember{
		sourceDirectory("other/", 0o755, time.Time{}),
		sourceRegular(
			"other/file",
			0o600,
			[]byte("y"),
			time.Time{},
		),
	})
	for _, archive := range [][]byte{
		append(bytes.Clone(valid), []byte("trailing")...),
		append(bytes.Clone(valid), secondStream...),
	} {
		snapshotter := &Snapshotter{tempRoot: t.TempDir()}
		prepared, err := snapshotter.canonicalize(
			context.Background(),
			binding,
			bytes.NewReader(archive),
		)
		prepared.Destroy()
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("trailing data error=%v", err)
		}
	}
}

func TestSnapshotterRejectsUntrustedRedirectWithoutSecondRequest(
	t *testing.T,
) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	for _, location := range []string{
		"http://codeload.github.com/repository/archive",
		"https://evil.example/repository/archive",
		"https://token@codeload.github.com/repository/archive",
		"https://codeload.github.com:8443/repository/archive",
		"https://codeload.github.com/repository/archive#fragment",
	} {
		location := location
		t.Run(location, func(t *testing.T) {
			calls := 0
			snapshotter := &Snapshotter{
				http: &http.Client{
					Transport: sourceRoundTripFunc(func(
						*http.Request,
					) (*http.Response, error) {
						calls++
						if calls != 1 {
							t.Fatal("untrusted redirect was followed")
						}
						return sourceResponse(
							http.StatusFound,
							nil,
							map[string]string{
								"Location": location,
							},
						), nil
					}),
					CheckRedirect: func(
						*http.Request,
						[]*http.Request,
					) error {
						return http.ErrUseLastResponse
					},
				},
			}
			body, err := snapshotter.openArchive(
				context.Background(),
				binding.Repository,
				[]byte("ghs_test_token_1234567890"),
			)
			if body != nil {
				body.Close()
			}
			if !errors.Is(err, ErrUnavailable) || calls != 1 {
				t.Fatalf("redirect error=%v calls=%d", err, calls)
			}
		})
	}
}

func TestSnapshotFactsRejectSourceSubstitution(t *testing.T) {
	t.Parallel()
	binding := newSnapshotTestBinding(t)
	bindingDigest, err := binding.Digest()
	if err != nil {
		t.Fatal(err)
	}
	base := SnapshotV1{
		SchemaVersion:      SnapshotSchemaV1,
		InputID:            binding.InputID,
		InputDigest:        binding.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       binding.SourceDigest,
		Repository:         binding.Repository,
		WorkspaceDigest:    "sha256:" + strings.Repeat("f", 64),
		SizeBytes:          1024,
		FileCount:          1,
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*SnapshotV1)
	}{
		{
			name: "input id",
			mutate: func(value *SnapshotV1) {
				value.InputID = uuid.NewString()
			},
		},
		{
			name: "source digest",
			mutate: func(value *SnapshotV1) {
				value.SourceDigest =
					"sha256:" + strings.Repeat("e", 64)
			},
		},
		{
			name: "repository",
			mutate: func(value *SnapshotV1) {
				value.Repository.RepositoryID = "999"
			},
		},
	}
	for _, testCase := range tests {
		changed := base
		testCase.mutate(&changed)
		if changed.Validate() == nil {
			t.Fatalf("%s substitution was accepted", testCase.name)
		}
	}
}

func assertCanonicalWorkspace(t *testing.T, content []byte) {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(content))
	expected := []struct {
		name     string
		mode     int64
		typeflag byte
		linkname string
		body     string
	}{
		{
			name: "current.go", mode: 0o777,
			typeflag: tar.TypeSymlink, linkname: "src/main.go",
		},
		{
			name: "run.sh", mode: 0o755,
			typeflag: tar.TypeReg, body: "#!/bin/sh\n",
		},
		{
			name: "src/", mode: 0o755,
			typeflag: tar.TypeDir,
		},
		{
			name: "src/main.go", mode: 0o644,
			typeflag: tar.TypeReg, body: "package main\n",
		},
	}
	epoch := time.Unix(0, 0).UTC()
	for index, want := range expected {
		header, err := reader.Next()
		if err != nil {
			t.Fatalf("canonical entry %d: %v", index, err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != want.name ||
			header.Mode != want.mode ||
			header.Typeflag != want.typeflag ||
			header.Linkname != want.linkname ||
			string(body) != want.body ||
			header.Uid != 0 ||
			header.Gid != 0 ||
			!header.ModTime.Equal(epoch) {
			t.Fatalf(
				"canonical entry %d drifted: header=%#v body=%q",
				index,
				header,
				body,
			)
		}
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("canonical archive has extra entries: %v", err)
	}
}

func readPrepared(t *testing.T, prepared *Prepared) []byte {
	t.Helper()
	reader, err := prepared.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

type snapshotTestFixture struct {
	broker        *githubapp.Broker
	binding       taskinput.BindingV2
	token         string
	tokenRequests int
}

func newSnapshotTestFixture(t *testing.T) *snapshotTestFixture {
	t.Helper()
	binding := newSnapshotTestBinding(t)
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	fixture := &snapshotTestFixture{
		binding: binding,
		token:   "ghs_snapshot_test_token_1234567890",
	}
	tokenTransport := sourceRoundTripFunc(func(
		request *http.Request,
	) (*http.Response, error) {
		fixture.tokenRequests++
		if request.Method != http.MethodPost ||
			request.URL.String() !=
				"https://api.github.com/app/installations/987654/access_tokens" ||
			!strings.HasPrefix(
				request.Header.Get("Authorization"),
				"Bearer ",
			) {
			t.Fatalf("unexpected token request: %#v", request)
		}
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		var requestBody struct {
			RepositoryIDs []uint64          `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if json.Unmarshal(raw, &requestBody) != nil ||
			len(requestBody.RepositoryIDs) != 1 ||
			requestBody.RepositoryIDs[0] != 42 ||
			len(requestBody.Permissions) != 1 ||
			requestBody.Permissions["contents"] != "read" {
			t.Fatalf("overbroad source token request: %s", raw)
		}
		responseBody, err := json.Marshal(map[string]any{
			"token":      fixture.token,
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
			"permissions": map[string]string{
				"contents": "read",
			},
			"repositories": []map[string]any{{
				"id":   42,
				"name": binding.Repository.Name,
				"full_name": binding.Repository.Owner +
					"/" + binding.Repository.Name,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return sourceResponse(http.StatusCreated, responseBody, nil), nil
	})
	broker, err := githubapp.NewBroker(
		sourceConnection{
			connection: githubapp.ConnectionV1{
				ConnectionID:   binding.Repository.ConnectionID,
				Provider:       taskinput.GitProviderGitHub,
				Host:           taskinput.GitHubHost,
				IssuerID:       "Iv1snapshotclient",
				InstallationID: 987654,
				PrivateKeyRef:  "mounted:github-app-key",
				Active:         true,
			},
		},
		sourcePrivateKey{content: bytes.Clone(keyPEM)},
		&http.Client{Transport: tokenTransport},
		func() time.Time { return now },
	)
	clear(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fixture.broker = broker
	return fixture
}

func newSnapshotTestBinding(t *testing.T) taskinput.BindingV2 {
	t.Helper()
	input, err := taskinput.NewGitHubInput(
		"owner-a",
		uuid.NewString(),
		"sha256:"+strings.Repeat("1", 64),
		taskinput.GitRepositoryV1{
			Provider:      taskinput.GitProviderGitHub,
			Host:          taskinput.GitHubHost,
			ConnectionID:  uuid.NewString(),
			RepositoryID:  "42",
			Owner:         "YingSuiAI",
			Name:          "dirextalk-agent",
			BaseCommitSHA: strings.Repeat("a", 40),
			BaseRef:       "refs/heads/codex/native-agent-v2",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := input.Binding()
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

type sourceMember struct {
	header tar.Header
	body   []byte
}

func sourceDirectory(
	name string,
	mode int64,
	modified time.Time,
) sourceMember {
	return sourceMember{header: tar.Header{
		Name:     name,
		Mode:     mode,
		Typeflag: tar.TypeDir,
		ModTime:  modified,
		Uid:      1000,
		Gid:      1000,
	}}
}

func sourceRegular(
	name string,
	mode int64,
	body []byte,
	modified time.Time,
) sourceMember {
	return sourceMember{
		header: tar.Header{
			Name:     name,
			Mode:     mode,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
			ModTime:  modified,
			Uid:      1000,
			Gid:      1000,
		},
		body: bytes.Clone(body),
	}
}

func sourceSymlink(
	name,
	target string,
	modified time.Time,
) sourceMember {
	return sourceMember{header: tar.Header{
		Name:     name,
		Mode:     0o700,
		Typeflag: tar.TypeSymlink,
		Linkname: target,
		ModTime:  modified,
		Uid:      1000,
		Gid:      1000,
	}}
}

func sourceGzip(t *testing.T, members []sourceMember) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := member.header
		if err := tarWriter.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if len(member.body) != 0 {
			if _, err := tarWriter.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
		clear(member.body)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type sourceConnection struct {
	connection githubapp.ConnectionV1
}

func (source sourceConnection) LoadGitHubAppConnection(
	_ context.Context,
	connectionID string,
) (githubapp.ConnectionV1, error) {
	if source.connection.ConnectionID != connectionID {
		return githubapp.ConnectionV1{}, githubapp.ErrUnavailable
	}
	return source.connection, nil
}

type sourcePrivateKey struct {
	content []byte
}

func (source sourcePrivateKey) MaterializeGitHubAppPrivateKey(
	_ context.Context,
	_ string,
	use func([]byte) error,
) error {
	content := bytes.Clone(source.content)
	defer clear(content)
	return use(content)
}

type sourceRoundTripFunc func(*http.Request) (*http.Response, error)

func (function sourceRoundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}

func sourceResponse(
	status int,
	body []byte,
	headers map[string]string,
) *http.Response {
	header := make(http.Header)
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}
