// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The workload commands run inside the workload itself (a CI job, a pod, a
// service): they use its key file and PAP/1, never a user session.
func workloadCommands() map[string]command {
	return map[string]command{
		"workload init": {"workload init --key-file FILE", workloadInit},
		"workload enroll": {
			"workload enroll --key-file FILE --server URL [--enrollment-token-file FILE] [--github | --kubernetes-token FILE | --gitlab-token-env VAR | --spiffe-token FILE | --gcp | --aws] [--org ID] [--declared-release sha256:…]",
			workloadEnroll,
		},
		"workload token": {"workload token --key-file FILE [--github | --kubernetes-token FILE | --gitlab-token-env VAR | --spiffe-token FILE | --gcp | --aws] [--declared-release sha256:…] [--out FILE]", workloadToken},
	}
}

// readSecret reads a token from a file, trimmed.
func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the user's own file
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func workloadInit(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("workload init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path := fs.String("key-file", "", "where to write the new key (0600; never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errUsage
	}
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		return err
	}
	if err := workloadclient.WriteKeyFile(*path, kf, false); err != nil {
		return err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	_, err = fmt.Fprintf(a.stdout, "new workload key in %s (fingerprint %s)\n", *path, jws.Thumbprint(pub))
	return err
}

// attestationFlags declares the attestation sources.
type attestationFlags struct {
	github     *bool
	kubernetes *string
	gitlabEnv  *string
	spiffe     *string
	gcp        *bool
	aws        *bool
}

func declareAttestation(fs *flag.FlagSet) attestationFlags {
	return attestationFlags{
		github:     fs.Bool("github", false, "attest with this GitHub Actions job's OIDC token (the job needs id-token: write)"),
		kubernetes: fs.String("kubernetes-token", "", "attest with this projected service-account token file"),
		gitlabEnv: fs.String("gitlab-token-env", "", "attest with the GitLab CI ID token in this environment variable "+
			"(id_tokens with aud pantherclaw:<org>)"),
		spiffe: fs.String("spiffe-token", "", "attest with the JWT-SVID in this file (audience pantherclaw:<org>); "+
			"it is read again at each renewal"),
		gcp: fs.Bool("gcp", false, "attest with a Google-signed ID token from the GCP metadata server (audience pantherclaw:<org>)"),
		aws: fs.Bool("aws", false, "attest with a signed sts:GetCallerIdentity request (role session credentials from AWS_ACCESS_KEY_ID, "+
			"AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN; AWS_REGION picks the regional endpoint)"),
	}
}

// errAttestationSources is returned when more than one source is given.
var errAttestationSources = errors.New("use one of --github, --kubernetes-token, --gitlab-token-env, --spiffe-token, --gcp and --aws, not both")

// check refuses more than one attestation source.
func (f attestationFlags) check() error {
	n := 0
	for _, set := range []bool{*f.github, *f.kubernetes != "", *f.gitlabEnv != "", *f.spiffe != "", *f.gcp, *f.aws} {
		if set {
			n++
		}
	}
	if n > 1 {
		return errAttestationSources
	}
	return nil
}

// attestation returns the platform token for org's audience, or nil.
func (f attestationFlags) attestation(ctx context.Context, a *app, org ids.OrgID) (*pantherclawv1.Attestation, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	switch {
	case *f.gitlabEnv != "":
		tok := strings.TrimSpace(os.Getenv(*f.gitlabEnv))
		if tok == "" {
			return nil, fmt.Errorf("the environment variable %s holds no GitLab ID token", *f.gitlabEnv)
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_GITLAB_CI, Token: tok}, nil
	case *f.spiffe != "":
		tok, err := readSecret(*f.spiffe)
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_SPIFFE_JWT, Token: tok}, nil
	case *f.gcp:
		if org.IsZero() {
			return nil, errors.New("the org is unknown: pass --org")
		}
		tok, err := gcpIdentity(ctx, a, "pantherclaw:"+org.String())
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_GCP_WORKLOAD, Token: tok}, nil
	case *f.aws:
		if org.IsZero() {
			return nil, errors.New("the org is unknown: pass --org")
		}
		creds, err := awsFromEnv(a)
		if err != nil {
			return nil, err
		}
		tok, err := awsAttestation(creds, "pantherclaw:"+org.String(), time.Now())
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_AWS_IAM, Token: tok}, nil
	case *f.github:
		if org.IsZero() {
			return nil, errors.New("the org is unknown: pass --org")
		}
		tok, err := githubOIDC(ctx, a, "pantherclaw:"+org.String())
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_GITHUB_ACTIONS, Token: tok}, nil
	case *f.kubernetes != "":
		tok, err := readSecret(*f.kubernetes)
		if err != nil {
			return nil, err
		}
		return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_KUBERNETES, Token: tok}, nil
	}
	return nil, nil
}

// githubOIDC asks the GitHub Actions runtime for an OIDC token with
// audience (ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN are set for jobs with
// the id-token: write permission).
func githubOIDC(ctx context.Context, a *app, audience string) (string, error) {
	reqURL, ok1 := a.env("ACTIONS_ID_TOKEN_REQUEST_URL")
	bearer, ok2 := a.env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if !ok1 || !ok2 || reqURL == "" || bearer == "" {
		return "", errors.New("not in a GitHub Actions job with id-token: write (ACTIONS_ID_TOKEN_REQUEST_URL is not set)")
	}
	u, err := url.Parse(reqURL)
	if err != nil || u.Scheme != "https" && u.Hostname() != "127.0.0.1" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL must be an https URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("github oidc: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github oidc: status %d", resp.StatusCode)
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Value == "" {
		return "", errors.New("github oidc: no token in the response")
	}
	return v.Value, nil
}

// gcpIdentity asks the GCP metadata server (GCE_METADATA_HOST, default
// metadata.google.internal) for an ID token of the instance's service
// account with audience, including the Compute Engine claims.
func gcpIdentity(ctx context.Context, a *app, audience string) (string, error) {
	host, ok := a.env("GCE_METADATA_HOST")
	if !ok || host == "" {
		host = "metadata.google.internal"
	}
	u := url.URL{
		Scheme: "http", Host: host, Path: "/computeMetadata/v1/instance/service-accounts/default/identity",
		RawQuery: url.Values{"audience": {audience}, "format": {"full"}}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp metadata: status %d", resp.StatusCode)
	}
	tok := strings.TrimSpace(string(b))
	if strings.Count(tok, ".") != 2 {
		return "", errors.New("gcp metadata: no ID token in the response")
	}
	return tok, nil
}

func (a *app) workloadClient(server string, kf workloadclient.KeyFile) (pantherclawv1connect.WorkloadServiceClient, error) {
	return a.workloadClientAt(server, kf, nil)
}

// workloadClientAt is WorkloadService at server, signing with the key file's
// key and sending token's workload token when token is not nil.
func (a *app) workloadClientAt(server string, kf workloadclient.KeyFile, token func() string) (pantherclawv1connect.WorkloadServiceClient, error) {
	base, err := checkServer(server)
	if err != nil {
		return nil, err
	}
	key, err := kf.Key()
	if err != nil {
		return nil, err
	}
	rt := a.http.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	hc := &http.Client{Timeout: a.http.Timeout, CheckRedirect: a.http.CheckRedirect, Transport: &workloadclient.Transport{Key: key, Base: rt, Token: token}}
	return pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base))), nil
}

func workloadEnroll(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("workload enroll", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path, server := fs.String("key-file", "", "workload key file (from pclaw workload init)"), fs.String("server", "", "PantherClaw server URL")
	tokenFile, orgFlag := fs.String("enrollment-token-file", "", "file holding the owner's pce_ enrollment token"),
		fs.String("org", "", "org id (when enrolling with an attestation only)")
	declared := fs.String("declared-release", "", "release digest the workload reports about itself (recorded as declared)")
	att := declareAttestation(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *server == "" || fs.NArg() != 0 {
		return errUsage
	}
	kf, err := workloadclient.ReadKeyFile(*path)
	if err != nil {
		return err
	}
	req := &pantherclawv1.EnrollRequest{DeclaredReleaseDigest: *declared}
	var org ids.OrgID
	if *orgFlag != "" {
		if org, err = ids.Parse[ids.Org](*orgFlag); err != nil {
			return errors.New("--org must be an org id")
		}
	}
	if *tokenFile != "" {
		if req.EnrollmentToken, err = readSecret(*tokenFile); err != nil {
			return err
		}
		tok, err := credential.Parse(credential.EnrollmentToken, req.EnrollmentToken)
		if err != nil {
			return errors.New("the enrollment token file does not hold a pce_ token")
		}
		org = tok.Org()
	}
	if req.Attestation, err = att.attestation(ctx, a, org); err != nil {
		return err
	}
	if req.EnrollmentToken == "" && req.Attestation == nil {
		return errors.New("enrolling needs an enrollment token, an attestation, or both")
	}
	key, _ := kf.Key()
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return err
	}
	req.PublicJwk = string(jwk)
	wc, err := a.workloadClient(*server, kf)
	if err != nil {
		return err
	}
	res, err := wc.Enroll(ctx, req)
	if err != nil {
		return err
	}
	kf.Identifier, kf.Server = res.GetIdentifier(), *server
	if err := workloadclient.WriteKeyFile(*path, kf, true); err != nil {
		return err
	}
	if res.GetState() == pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED {
		_, err = fmt.Fprintf(a.stdout, "enrolled and admitted: instance %s (L%d)\n", res.GetInstanceId(), res.GetAttestationLevel())
		return err
	}
	_, err = fmt.Fprintf(a.stdout, "enrolled: instance %s is waiting for admission.\nFingerprint: %s\n"+
		"The agent's owner checks the fingerprint and runs: pclaw instance admit %s --fingerprint %s\n",
		res.GetInstanceId(), res.GetFingerprint(), res.GetInstanceId(), res.GetFingerprint())
	return err
}

func workloadToken(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("workload token", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	path, out := fs.String("key-file", "", "enrolled workload key file"), fs.String("out", "", "write the token here (0600) instead of stdout")
	declared := fs.String("declared-release", "", "release digest the workload reports about itself")
	att := declareAttestation(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errUsage
	}
	kf, err := workloadclient.ReadKeyFile(*path)
	if err != nil {
		return err
	}
	inst, err := pap.ParseInstance(kf.Identifier)
	if err != nil || kf.Server == "" {
		return errors.New("the key file is not enrolled yet: run pclaw workload enroll")
	}
	req := &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier, DeclaredReleaseDigest: *declared}
	if req.Attestation, err = att.attestation(ctx, a, inst.Org); err != nil {
		return err
	}
	wc, err := a.workloadClient(kf.Server, kf)
	if err != nil {
		return err
	}
	res, err := wc.IssueToken(ctx, req)
	if err != nil {
		return err
	}
	if *out != "" {
		return os.WriteFile(*out, []byte(res.GetWorkloadToken()+"\n"), 0o600)
	}
	_, err = fmt.Fprintln(a.stdout, res.GetWorkloadToken())
	return err
}
