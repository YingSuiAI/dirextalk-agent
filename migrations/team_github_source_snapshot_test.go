package migrations

import (
	"strings"
	"testing"
)

func TestTeamGitHubSourceSnapshotMigrationBindsImmutableArtifact(
	t *testing.T,
) {
	t.Parallel()
	raw, err := Files.ReadFile(
		"000056_team_github_source_snapshot.up.sql",
	)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, fragment := range []string{
		"CREATE TABLE team_github_source_snapshots",
		"UNIQUE (input_id, input_digest, connection_id)",
		"FOREIGN KEY (input_id, input_digest, source_digest)",
		"REFERENCES team_task_inputs",
		"workspace_size_bytes BETWEEN 1 AND 1073741824",
		"repository_file_count BETWEEN 1 AND 100000",
		"'source-snapshots/github/'",
		"'dirextalk.agent.github-source-fact/v1'",
		"'dirextalk.agent.github-source-snapshot/v1'",
		"'dirextalk.agent.github-source-artifact/v1'",
		"artifact->>'provider' <> 'aws_s3'",
		"artifact->>'media_type' <> 'application/x-tar'",
		"snapshot->'repository' = input.input_json->'repository'",
		"connection.owner_id = input.owner_id",
		"CREATE TRIGGER team_github_source_snapshots_bound_insert",
		"CREATE TRIGGER team_github_source_snapshots_immutable",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf(
				"GitHub source snapshot migration missing %q",
				fragment,
			)
		}
	}
	lower := strings.ToLower(sql)
	for _, forbidden := range []string{
		"installation_token",
		"personal_access_token",
		"private_key",
		"model_api_key",
		"github_pat_",
		"ghs_",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf(
				"GitHub source snapshot persists forbidden material %q",
				forbidden,
			)
		}
	}
}
