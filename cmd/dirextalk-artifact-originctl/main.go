// dirextalk-artifact-originctl creates and recovers the fixed two-Region
// first-party artifact origin, then conditionally publishes reviewed pinned
// Knowledge artifacts. It accepts no AWS credentials or mutable object keys.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/artifactorigin"
)

const (
	usageMessage   = "artifact-origin usage error\n"
	prepareMessage = "artifact-origin preparation failed\n"
	publishMessage = "artifact publication failed\n"
	verifyMessage  = "artifact verification failed\n"
	outputMessage  = "artifact-origin receipt write failed\n"
	maxReceiptSize = 64 << 10
)

var (
	prepareOrigin    = artifactorigin.PrepareDefault
	publishArtifact  = artifactorigin.PublishDefault
	verifyArtifact   = artifactorigin.VerifyPublishedDefault
	writeReceiptFile = writeExclusiveJSON
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	if ctx == nil || len(arguments) == 0 {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	switch arguments[0] {
	case "prepare":
		return runPrepare(ctx, arguments[1:], stdout, stderr)
	case "publish":
		return runArtifact(ctx, arguments[1:], stdout, stderr, false)
	case "verify":
		return runArtifact(ctx, arguments[1:], stdout, stderr, true)
	default:
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
}

func runPrepare(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := artifactorigin.PrepareOptions{}
	receiptOutput := ""
	flags.StringVar(&options.AccountID, "account-id", "", "")
	flags.StringVar(&options.Region, "region", "", "")
	flags.StringVar(&options.Domain, "domain", "", "")
	flags.StringVar(&options.HostedZoneID, "hosted-zone-id", "", "")
	flags.StringVar(&receiptOutput, "receipt-output", "", "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || options.AccountID == "" || options.Region != artifactorigin.StorageRegion ||
		options.Domain != artifactorigin.DomainName || options.HostedZoneID == "" || receiptOutput == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	operationContext, cancel := context.WithTimeout(ctx, 45*time.Minute)
	receipt, err := prepareOrigin(operationContext, options, time.Now)
	cancel()
	if err != nil {
		_, _ = io.WriteString(stderr, prepareMessage)
		return 1
	}
	return emitReceipt(stdout, stderr, receiptOutput, receipt)
}

func runArtifact(ctx context.Context, arguments []string, stdout, stderr io.Writer, verify bool) int {
	flags := flag.NewFlagSet("artifact", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	accountID, region, artifactID, localPath, originPath, receiptOutput := "", "", "", "", "", ""
	flags.StringVar(&accountID, "account-id", "", "")
	flags.StringVar(&region, "region", "", "")
	flags.StringVar(&artifactID, "artifact-id", "", "")
	flags.StringVar(&localPath, "file", "", "")
	flags.StringVar(&originPath, "origin-receipt", "", "")
	flags.StringVar(&receiptOutput, "receipt-output", "", "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || accountID == "" || region != artifactorigin.StorageRegion || artifactID == "" || localPath == "" || originPath == "" || receiptOutput == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	origin, err := readOriginReceipt(originPath)
	if err != nil || origin.AccountID != accountID || origin.StorageRegion != region {
		_, _ = io.WriteString(stderr, chooseMessage(verify))
		return 1
	}
	artifact, err := artifactorigin.PinnedKnowledgeArtifact(artifactID)
	if err != nil {
		_, _ = io.WriteString(stderr, chooseMessage(verify))
		return 1
	}
	operationContext, cancel := context.WithTimeout(ctx, 30*time.Minute)
	var receipt artifactorigin.ArtifactReceipt
	if verify {
		receipt, err = verifyArtifact(operationContext, origin, artifact, localPath, time.Now)
	} else {
		receipt, err = publishArtifact(operationContext, origin, artifact, localPath, time.Now)
	}
	cancel()
	if err != nil {
		_, _ = io.WriteString(stderr, chooseMessage(verify))
		return 1
	}
	return emitReceipt(stdout, stderr, receiptOutput, receipt)
}

func chooseMessage(verify bool) string {
	if verify {
		return verifyMessage
	}
	return publishMessage
}

func readOriginReceipt(name string) (artifactorigin.OriginReceipt, error) {
	var receipt artifactorigin.OriginReceipt
	payload, err := readBoundedRegularFile(name, maxReceiptSize)
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || receipt.Validate() != nil {
		return artifactorigin.OriginReceipt{}, artifactorigin.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return artifactorigin.OriginReceipt{}, artifactorigin.ErrInvalid
	}
	return receipt, nil
}

func readBoundedRegularFile(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, artifactorigin.ErrInvalid
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, artifactorigin.ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, artifactorigin.ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > limit {
		return nil, artifactorigin.ErrInvalid
	}
	return payload, nil
}

func emitReceipt(stdout, stderr io.Writer, name string, receipt any) int {
	if err := writeReceiptFile(name, receipt); err != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(receipt); err != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}

func writeExclusiveJSON(name string, value any) (err error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if !complete || err != nil {
			_ = os.Remove(name)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}
