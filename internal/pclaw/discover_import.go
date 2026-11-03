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
	"maps"
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
// Every finding is sent, in imports of at most maxImportFindings. A recording
// sent in more than one import says so in each (NoteFindings): no one import
// saw every agent, so none counts an agent missing.

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
	s, err := a.session()
	if err != nil {
		return err
	}
	client := pantherclawv1connect.NewSaasDiscoveryServiceClient(s.connect())
	reqs := importRequests(r)
	for i, req := range reqs {
		res, err := client.ImportSaasReport(ctx, req)
		if err != nil {
			if i > 0 {
				_, _ = fmt.Fprintf(a.stderr, "imports 1-%d of %d were recorded; the rest were not sent\n", i, len(reqs))
			}
			return err
		}
		for name, why := range res.GetScan().GetNotScanned() {
			_, _ = fmt.Fprintf(a.stderr, "not scanned: %s: %s\n", name, why)
		}
		if err := a.print(res); err != nil {
			return err
		}
	}
	return nil
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

// importRequests are r as the API takes it: every finding, at most
// maxImportFindings to an import. More than one import notes, in each, that
// the recording was sent in parts, so none of them counts misses.
func importRequests(r *domain.Report) []*pb.ImportSaasReportRequest {
	r.MarkUnread()
	parts := max(1, (len(r.Findings)+maxImportFindings-1)/maxImportFindings)
	notScanned := r.NotScanned
	if parts > 1 {
		notScanned = maps.Clone(r.NotScanned)
		why := strconv.Itoa(len(r.Findings)) + " findings were sent in " + strconv.Itoa(parts) +
			" imports of at most " + strconv.Itoa(maxImportFindings) + "; no one import saw every agent"
		if had := notScanned[domain.NoteFindings]; had != "" {
			why = had + "; " + why
		}
		notScanned[domain.NoteFindings] = why
	}
	reqs := make([]*pb.ImportSaasReportRequest, 0, parts)
	for part := range parts {
		req := &pb.ImportSaasReportRequest{
			Source: r.Source, Tenant: r.Tenant, Scanned: r.Scanned, NotScanned: notScanned, Counts: r.Counts,
		}
		lo, hi := min(part*maxImportFindings, len(r.Findings)), min((part+1)*maxImportFindings, len(r.Findings))
		for _, f := range r.Findings[lo:hi] {
			req.Findings = append(req.Findings, &pb.SaasReportFinding{Kind: f.Kind, Key: hex.EncodeToString(f.Key[:]), Attributes: f.Attributes})
		}
		reqs = append(reqs, req)
	}
	return reqs
}
