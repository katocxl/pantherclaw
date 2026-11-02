// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/parse"
)

// `pclaw discover import` (G0 M26 D407; F924) parses a recording an admin
// exported from Microsoft Copilot Studio or ChatGPT Enterprise on this machine
// and sends the server what the parser kept: metadata, never a conversation.
// Findings past one request's limit are reported not scanned, never dropped
// silently.

// maxImportFindings is the most findings one import carries (the API's limit).
const maxImportFindings = 200

func init() {
	commands["discover import"] = command{
		usage: "discover import --source copilot_studio|chatgpt_enterprise --file <recording.json>",
		run:   discoverImport,
	}
}

func discoverImport(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("discover import", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	source := fs.String("source", "", "copilot_studio or chatgpt_enterprise")
	file := fs.String("file", "", "the exported recording")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *file == "" {
		return errUsage
	}
	raw, err := readRecording(*file)
	if err != nil {
		return err
	}
	r, err := parse.Recording(*source, raw)
	if err != nil {
		return err
	}
	req := importRequest(r)
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewSaasDiscoveryServiceClient(s.connect()).ImportSaasReport(ctx, req)
	if err != nil {
		return err
	}
	for name, why := range res.GetScan().GetNotScanned() {
		_, _ = fmt.Fprintf(a.stderr, "not scanned: %s: %s\n", name, why)
	}
	return a.print(res)
}

// readRecording reads at most parse.MaxRecording and one byte more, which the
// parser refuses.
func readRecording(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the file the person named
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, parse.MaxRecording+1))
	if err != nil {
		return nil, errors.Join(errors.New("the recording could not be read"), err)
	}
	return raw, nil
}

// importRequest is r as the API takes it.
func importRequest(r *domain.Report) *pb.ImportSaasReportRequest {
	findings := r.Findings
	if len(findings) > maxImportFindings {
		r.Note(domain.NoteFindings, strconv.Itoa(len(findings)-maxImportFindings)+" findings past one import's limit were not sent")
		findings = findings[:maxImportFindings]
	}
	req := &pb.ImportSaasReportRequest{
		Source: r.Source, Tenant: r.Tenant, Scanned: r.Scanned, NotScanned: r.NotScanned, Counts: r.Counts,
	}
	for _, f := range findings {
		req.Findings = append(req.Findings, &pb.SaasReportFinding{Kind: f.Kind, Key: hex.EncodeToString(f.Key[:]), Attributes: f.Attributes})
	}
	return req
}
