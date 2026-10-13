// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw pack create|list|get|download (G0 M7 design decision 15, HR-196).
// A pack is built by the server from your permissions when it runs; it is
// a ZIP with a signed manifest that `pclaw verify` checks offline.

func init() {
	commands["pack create"] = command{
		usage: "pack create (--txn ID [--txn ID]… | --run ID | --agent ID | --from TIME --to TIME) [--from TIME --to TIME] " +
			"[--include receipts,versions,approvals,containment[,captures]]",
		run: packCreate,
	}
	commands["pack list"] = rpc("pack list", 0, func(fs *flag.FlagSet) call {
		n, tok := paging(fs)
		return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
			return evidenceClient(c).ListEvidencePacks(ctx, &pantherclawv1.ListEvidencePacksRequest{PageSize: size(n), PageToken: *tok})
		}
	})
	commands["pack get"] = rpc("pack get ID", 1, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			return evidenceClient(c).GetEvidencePack(ctx, &pantherclawv1.GetEvidencePackRequest{Id: a[0]})
		}
	})
	commands["pack download"] = command{usage: "pack download ID --out FILE", run: packDownload}
}

// defaultInclude is what a pack holds unless --include says otherwise.
const defaultInclude = "receipts,versions,approvals,containment"

func includeOf(s string) (*pantherclawv1.PackContents, error) {
	out := &pantherclawv1.PackContents{}
	for part := range strings.SplitSeq(s, ",") {
		switch strings.TrimSpace(part) {
		case "receipts":
			out.Receipts = true
		case "versions":
			out.Versions = true
		case "approvals":
			out.Approvals = true
		case "containment":
			out.Containment = true
		case "captures":
			out.Captures = true
		case "":
		default:
			return nil, fmt.Errorf("--include: unknown part %q", part)
		}
	}
	return out, nil
}

func packTime(flagName, s string) (*timestamppb.Timestamp, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("--%s must be an RFC 3339 time", flagName)
	}
	return timestamppb.New(t), nil
}

func packCreate(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("pack create", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var txns list
	fs.Var(&txns, "txn", "a transaction (repeat, at most 1,000)")
	run := fs.String("run", "", "every transaction of this run")
	agent := fs.String("agent", "", "every transaction of this agent")
	from := fs.String("from", "", "start of a time range (RFC 3339); with --run or --agent it narrows them")
	to := fs.String("to", "", "end of the time range (RFC 3339)")
	include := fs.String("include", defaultInclude, "what to include: receipts, versions, approvals, containment, captures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scopes := 0
	for _, set := range []bool{len(txns) > 0, *run != "", *agent != ""} {
		if set {
			scopes++
		}
	}
	ranged := *from != "" || *to != ""
	if fs.NArg() != 0 || scopes > 1 || (scopes == 0 && !ranged) || (ranged && (*from == "" || *to == "")) || (len(txns) > 0 && ranged) {
		return errUsage
	}
	in, err := includeOf(*include)
	if err != nil {
		return err
	}
	req := &pantherclawv1.CreateEvidencePackRequest{Include: in}
	var tr *pantherclawv1.PackTimeRange
	if ranged {
		start, err := packTime("from", *from)
		if err != nil {
			return err
		}
		end, err := packTime("to", *to)
		if err != nil {
			return err
		}
		tr = &pantherclawv1.PackTimeRange{StartTime: start, EndTime: end}
	}
	switch {
	case len(txns) > 0:
		req.Scope = &pantherclawv1.CreateEvidencePackRequest_Transactions{Transactions: &pantherclawv1.PackTransactions{Ids: txns}}
	case *run != "":
		req.Scope, req.Within = &pantherclawv1.CreateEvidencePackRequest_RunId{RunId: *run}, tr
	case *agent != "":
		req.Scope, req.Within = &pantherclawv1.CreateEvidencePackRequest_AgentId{AgentId: *agent}, tr
	default:
		req.Scope = &pantherclawv1.CreateEvidencePackRequest_TimeRange{TimeRange: tr}
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	res, err := evidenceClient(c).CreateEvidencePack(ctx, req)
	if err != nil {
		return err
	}
	return a.print(res)
}

// errPackContent reports a download that is not the content the server
// described.
var errPackContent = errors.New("the downloaded pack does not match its size and SHA-256: try again")

func packDownload(ctx context.Context, a *app, args []string) error {
	if len(args) < 1 {
		return errUsage
	}
	fs := flag.NewFlagSet("pack download", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out := fs.String("out", "", "file to write (must not exist)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	stream, err := evidenceClient(c).DownloadEvidencePack(ctx, &pantherclawv1.DownloadEvidencePackRequest{Id: args[0]})
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	var buf bytes.Buffer
	var total int64 = -1
	var want []byte
	for {
		m, err := stream.Receive()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if total < 0 {
			total, want = m.GetTotalSize(), m.GetContentSha256()
			if total < 0 || total > pack.MaxContentBytes {
				return errPackContent
			}
		}
		if m.GetOffset() != int64(buf.Len()) || int64(buf.Len()+len(m.GetChunk())) > total {
			return errPackContent
		}
		buf.Write(m.GetChunk())
	}
	sum := sha256.Sum256(buf.Bytes())
	if int64(buf.Len()) != total || !bytes.Equal(sum[:], want) {
		return errPackContent
	}
	if err := writeNew(*out, buf.Bytes()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "Wrote the evidence pack (%d bytes) to %s. Check it offline with: pclaw verify %s --trust FILE\n",
		buf.Len(), *out, *out)
	return err
}

func evidenceClient(c clients) pantherclawv1connect.EvidenceServiceClient { return c.evidence }
