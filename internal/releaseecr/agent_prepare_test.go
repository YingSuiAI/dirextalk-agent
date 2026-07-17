package releaseecr

import (
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestAgentPreparerCreatesAndReceiptsOnlyAgentRepository(t *testing.T) {
	ecrClient := &fakeECR{repositories: make(map[string]ecrtypes.Repository)}
	runner := &fakeRunner{}
	preparer, err := NewAgent(validOptions(), Clients{Region: testRegion, STS: validSTS(), ECR: ecrClient}, runner)
	if err != nil {
		t.Fatal(err)
	}
	prepared := prepareSuccess(t, preparer)

	if prepared.Result.SchemaVersion != AgentResultSchemaV1 || len(prepared.Result.Repositories) != 1 {
		t.Fatalf("agent preparation receipt = %#v", prepared.Result)
	}
	repository := prepared.Result.Repositories[0]
	if repository.Component != "agent" || repository.Name != RepositoryAgent || !repository.Created {
		t.Fatalf("agent repository receipt = %#v", repository)
	}
	if len(ecrClient.createCalls) != 1 || aws.ToString(ecrClient.createCalls[0].RepositoryName) != RepositoryAgent {
		t.Fatalf("created repositories = %#v", ecrClient.createCalls)
	}
	if !slices.Equal(ecrClient.describeCalls, []string{RepositoryAgent, RepositoryAgent}) ||
		!slices.Equal(ecrClient.listTagCalls, []string{RepositoryAgent}) {
		t.Fatalf("agent preparation touched unexpected repositories: describe=%#v list_tags=%#v", ecrClient.describeCalls, ecrClient.listTagCalls)
	}
	if len(runner.commands) != 1 || runner.commands[0].executable != "docker" {
		t.Fatalf("publisher Docker session was not prepared exactly once: %#v", runner.commands)
	}
}

func TestAgentPreparerDoesNotInspectExistingWorkerOrReaperRepositories(t *testing.T) {
	ecrClient := &fakeECR{repositories: map[string]ecrtypes.Repository{
		RepositoryAgent:  validRepository(RepositoryAgent),
		RepositoryWorker: validRepository(RepositoryWorker),
		RepositoryReaper: validRepository(RepositoryReaper),
	}}
	preparer, err := NewAgent(validOptions(), Clients{Region: testRegion, STS: validSTS(), ECR: ecrClient}, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	prepared := prepareSuccess(t, preparer)
	if len(prepared.Result.Repositories) != 1 || prepared.Result.Repositories[0].Name != RepositoryAgent || prepared.Result.Repositories[0].Created {
		t.Fatalf("agent preparation result = %#v", prepared.Result.Repositories)
	}
	if !slices.Equal(ecrClient.describeCalls, []string{RepositoryAgent}) || !slices.Equal(ecrClient.listTagCalls, []string{RepositoryAgent}) {
		t.Fatalf("agent preparation inspected non-Agent repository: describe=%#v list_tags=%#v", ecrClient.describeCalls, ecrClient.listTagCalls)
	}
}
