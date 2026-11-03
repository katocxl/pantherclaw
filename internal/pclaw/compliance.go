// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// `pclaw compliance` (G0 M25 D311) reads a framework's coverage. It shows
// evidence and gaps, not a certification or statement of compliance. A signed
// report is `pclaw pack create --framework NAME --from TIME --to TIME`, and
// `pclaw verify` re-derives it offline.

var complianceFrameworks = []struct {
	name  string
	value pb.ComplianceFramework
}{
	{"OWASP_ASI", pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_OWASP_ASI},
	{"NIST_AI_RMF", pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_NIST_AI_RMF},
	{"EU_AI_ACT_DEPLOYER", pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_EU_AI_ACT_DEPLOYER},
	{"ISO_42001", pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_ISO_42001},
	{"SOC2", pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_SOC2},
}

func frameworkNames() string {
	names := make([]string, 0, len(complianceFrameworks))
	for _, f := range complianceFrameworks {
		names = append(names, f.name)
	}
	return strings.Join(names, ", ")
}

func frameworkOf(s string) (pb.ComplianceFramework, error) {
	for _, f := range complianceFrameworks {
		if f.name == s {
			return f.value, nil
		}
	}
	return 0, fmt.Errorf("--framework: one of %s", frameworkNames())
}

func complianceClient(c clients) pantherclawv1connect.ComplianceServiceClient { return c.compliance }

func init() {
	commands["compliance frameworks"] = rpc("compliance frameworks", 0, func(*flag.FlagSet) call {
		return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
			return complianceClient(c).ListFrameworks(ctx, &pb.ListFrameworksRequest{})
		}
	})
	commands["compliance coverage"] = rpc("compliance coverage NAME --from TIME --to TIME", 1, func(fs *flag.FlagSet) call {
		from := fs.String("from", "", "start of the period (RFC 3339)")
		to := fs.String("to", "", "end of the period (RFC 3339)")
		return func(ctx context.Context, c clients, a []string) (proto.Message, error) {
			fw, err := frameworkOf(a[0])
			if err != nil {
				return nil, err
			}
			start, err := packTime("from", *from)
			if err != nil {
				return nil, err
			}
			end, err := packTime("to", *to)
			if err != nil {
				return nil, err
			}
			return complianceClient(c).GetFrameworkCoverage(ctx, &pb.GetFrameworkCoverageRequest{Framework: fw, StartTime: start, EndTime: end})
		}
	})
	commands["compliance reports"] = rpc("compliance reports", 0, func(fs *flag.FlagSet) call {
		n, tok := paging(fs)
		return func(ctx context.Context, c clients, _ []string) (proto.Message, error) {
			return complianceClient(c).ListComplianceReports(ctx, &pb.ListComplianceReportsRequest{PageSize: size(n), PageToken: *tok})
		}
	})
}
