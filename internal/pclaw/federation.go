// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw federation … (G0 M35 D1046): an org's federation document, its
// key, its pairwise trusts with peer orgs (FD10), its listings (the agents
// a trusted peer may message), cross-org grants and the minimal receipts
// both sides keep. Trust confirmation and key rotation need a person's
// fresh security-key step-up (D1020, D1021); the server checks it.

func init() {
	for k, v := range federationCommands() {
		commands[k] = v
	}
}

// fedCall is one FederationService call.
type fedCall func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, args []string) (proto.Message, error)

// fedRPC is rpc for FederationService.
func fedRPC(usage string, nargs int, setup func(fs *flag.FlagSet) fedCall) command {
	return command{usage: usage, run: func(ctx context.Context, a *app, args []string) error {
		if len(args) < nargs {
			return errUsage
		}
		fs := flag.NewFlagSet(usage, flag.ContinueOnError)
		fs.SetOutput(a.stderr)
		fn := setup(fs)
		if err := fs.Parse(args[nargs:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errUsage
		}
		s, err := a.session()
		if err != nil {
			return err
		}
		res, err := fn(ctx, pantherclawv1connect.NewFederationServiceClient(s.connect()), args[:nargs])
		if err != nil {
			return stepUpHint(a, err)
		}
		return a.print(res)
	}}
}

// noFlags is a command without flags.
func noFlags(call fedCall) func(*flag.FlagSet) fedCall {
	return func(*flag.FlagSet) fedCall { return call }
}

func federationCommands() map[string]command {
	return map[string]command{
		"federation doc": fedRPC("federation doc", 0, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, _ []string) (proto.Message, error) {
				return c.GetFederationDocument(ctx, &pb.GetFederationDocumentRequest{})
			})),
		"federation endpoint": fedRPC("federation endpoint URL   (https: the gateway's public base URL peers call)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.SetFederationEndpoint(ctx, &pb.SetFederationEndpointRequest{FederationUrl: a[0]})
			})),
		"federation rotate": fedRPC("federation rotate   (needs your security key; the old key stays RETIRING 7 days)", 0, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, _ []string) (proto.Message, error) {
				return c.RotateFederationKey(ctx, &pb.RotateFederationKeyRequest{})
			})),
		"federation trust propose": fedRPC("federation trust propose PEER_DOC_URL   (https; shows the safety code to compare with the peer's admin)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.ProposeFederationTrust(ctx, &pb.ProposeFederationTrustRequest{PeerDocUrl: a[0]})
			})),
		"federation trust confirm": fedRPC("federation trust confirm TRUST_ID   (needs your security key; compare the safety code out of band first)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.ConfirmFederationTrust(ctx, &pb.ConfirmFederationTrustRequest{Id: a[0]})
			})),
		"federation trust revoke": fedRPC("federation trust revoke TRUST_ID   (takes effect at once)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.RevokeFederationTrust(ctx, &pb.RevokeFederationTrustRequest{Id: a[0]})
			})),
		"federation trust list": fedRPC("federation trust list [--include-revoked]", 0, func(fs *flag.FlagSet) fedCall {
			revoked := fs.Bool("include-revoked", false, "also list revoked trusts")
			return func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, _ []string) (proto.Message, error) {
				return c.ListFederationTrusts(ctx, &pb.ListFederationTrustsRequest{IncludeRevoked: *revoked})
			}
		}),
		"federation trust show": fedRPC("federation trust show TRUST_ID   (shows the safety code)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.GetFederationTrust(ctx, &pb.GetFederationTrustRequest{Id: a[0]})
			})),
		"federation listing create": fedRPC("federation listing create NAME --agent AGENT_ID --connection CONNECTION_ID --skill ID [--skill ID]...", 1,
			func(fs *flag.FlagSet) fedCall {
				agent := fs.String("agent", "", "the listed agent (required)")
				conn := fs.String("connection", "", "the a2a connection whose peer is that agent (required)")
				var skills list
				fs.Var(&skills, "skill", "a skill of the agent's card a peer may ask for (repeatable, at least one)")
				return func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
					if *agent == "" || *conn == "" || len(skills) == 0 {
						return nil, errors.New("--agent, --connection and at least one --skill are required")
					}
					return c.CreateFederationListing(ctx, &pb.CreateFederationListingRequest{
						Name: a[0], AgentId: *agent, ConnectionId: *conn, Skills: skills,
					})
				}
			}),
		"federation listing retire": fedRPC("federation listing retire LISTING_ID", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.RetireFederationListing(ctx, &pb.RetireFederationListingRequest{Id: a[0]})
			})),
		"federation peers": fedRPC("federation peers TRUST_ID   (the peer's listed agents and whether each verifies)", 1, noFlags(
			func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				return c.ListFederatedPeerAgents(ctx, &pb.ListFederatedPeerAgentsRequest{TrustId: a[0]})
			})),
		"federation grant issue": fedRPC("federation grant issue TRUST_ID --peer-agent pc:org/O/agent/A[/inst/I] --listing NAME --op OP [--op OP]... "+
			"--expires-at RFC3339|DURATION [--min-attestation 0..2] [--limits JSON]   (at most 90 days)", 1, func(fs *flag.FlagSet) fedCall {
			peer := fs.String("peer-agent", "", "the peer org's agent, as its token's sub (required)")
			listing := fs.String("listing", "", "our listing it may message (required)")
			var ops list
			fs.Var(&ops, "op", "federation.message.receive, federation.task.read or federation.task.cancel (repeatable)")
			expires := fs.String("expires-at", "", "when the grant ends: an RFC 3339 time or a duration such as 720h (required)")
			minAtt := fs.Int("min-attestation", 0, "the least attestation level the peer must state (0..2)")
			limits := fs.String("limits", "", "the grant's limits as a JSON object")
			return func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				if *peer == "" || *listing == "" || len(ops) == 0 || *expires == "" {
					return nil, errors.New("--peer-agent, --listing, --op and --expires-at are required")
				}
				exp, err := timeOf("expires-at", *expires)
				if err != nil {
					return nil, err
				}
				var lim []byte
				if *limits != "" {
					var probe map[string]any
					if json.Unmarshal([]byte(*limits), &probe) != nil {
						return nil, errors.New("--limits must be a JSON object")
					}
					lim = []byte(*limits)
				}
				return c.IssueCrossOrgGrant(ctx, &pb.IssueCrossOrgGrantRequest{
					TrustId: a[0], PeerAgent: *peer, Listing: *listing, Operations: ops, Limits: lim,
					MinAttestationLevel: int32(*minAtt), ExpireTime: exp, //nolint:gosec // G115: the server checks 0..2
				})
			}
		}),
		"federation grant revoke": fedRPC("federation grant revoke GRANT_ID --reason TEXT", 1, func(fs *flag.FlagSet) fedCall {
			reason := fs.String("reason", "", "why (required)")
			return func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, a []string) (proto.Message, error) {
				if *reason == "" {
					return nil, errors.New("--reason is required")
				}
				return c.RevokeCrossOrgGrant(ctx, &pb.RevokeCrossOrgGrantRequest{GrantId: a[0], Reason: *reason})
			}
		}),
		"federation receipts": fedRPC("federation receipts [--trust TRUST_ID] [--action ACTION_ID] [--page-size N] [--page-token T]", 0,
			func(fs *flag.FlagSet) fedCall {
				trust := fs.String("trust", "", "one trust only")
				action := fs.String("action", "", "one action only")
				size := fs.Int("page-size", 50, "at most this many (1 to 200)")
				token := fs.String("page-token", "", "the next_page_token of a previous page")
				return func(ctx context.Context, c pantherclawv1connect.FederationServiceClient, _ []string) (proto.Message, error) {
					if *size < 1 || *size > 200 {
						return nil, errors.New("--page-size must be 1..200")
					}
					return c.ListFederationReceipts(ctx, &pb.ListFederationReceiptsRequest{
						TrustId: *trust, ActionId: *action, PageSize: int32(*size), PageToken: *token,
					})
				}
			}),
	}
}
