// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package preflight verifies that the calling AWS principal holds the IAM actions
// tpm needs for its AWS-touching operations. It uses read-only
// iam:SimulatePrincipalPolicy against the caller ARN (from sts:GetCallerIdentity) —
// it evaluates, it never acts. This catches an under-permissioned account up front,
// before an operation fails mid-way.
//
// It mirrors attest's and ground's caller-permission check (provabl#16). The suite
// tools are deliberately decoupled — the evidence kernel is the only shared
// dependency, and it is stdlib-only — so each tool carries its own small copy of
// this generic check rather than introducing a shared AWS-SDK library. The per-tool
// action lists are documented in the suite's docs/required-permissions.md.
package preflight

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Result is the outcome of one permission check.
type Result struct {
	Name        string // the action, e.g. "iam:TagRole"
	Severity    string // "ok" | "error"
	Status      bool   // true when the action is permitted
	Detail      string // what was found
	Remediation string // actionable step when Status is false
}

type stsIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type iamSimAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, in *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// tpmRequiredActions are the AWS IAM actions tpm needs. tpm reads a NitroTPM quote
// on-instance (no AWS API for the quote); its AWS-touching operations are tagging
// the attested principal's role with attest:nitro-attested (iam:TagRole, via
// `tpm attest --role-arn`) and retrieving the instance EK public key — the NitroTPM
// trust anchor — via ec2:GetInstanceTpmEkPub. iam:SimulatePrincipalPolicy is
// included because this preflight itself needs it. See docs/required-permissions.md.
var tpmRequiredActions = []string{
	"sts:GetCallerIdentity",
	"iam:SimulatePrincipalPolicy",
	"iam:TagRole",
	"ec2:GetInstanceTpmEkPub",
}

// CheckCallerPermissions loads AWS config for the region and verifies the calling
// principal holds tpm's required actions. Fail-closed: a config/credential failure
// is an error result, not a silent pass.
func CheckCallerPermissions(ctx context.Context, region string) []Result {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return []Result{{
			Name: "AWS credentials", Severity: "error", Status: false,
			Detail:      err.Error(),
			Remediation: "Configure AWS credentials: aws configure or set AWS_PROFILE",
		}}
	}
	return check(ctx, sts.NewFromConfig(cfg), iam.NewFromConfig(cfg))
}

func check(ctx context.Context, stsSvc stsIdentityAPI, iamSvc iamSimAPI) []Result {
	ident, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return []Result{{
			Name: "Caller identity", Severity: "error", Status: false,
			Detail:      fmt.Sprintf("sts:GetCallerIdentity failed: %v", err),
			Remediation: "Ensure valid AWS credentials with sts:GetCallerIdentity",
		}}
	}
	callerARN := aws.ToString(ident.Arn)

	out, err := iamSvc.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(callerARN),
		ActionNames:     tpmRequiredActions,
	})
	if err != nil {
		return []Result{{
			Name: "IAM permission self-check", Severity: "error", Status: false,
			Detail:      fmt.Sprintf("iam:SimulatePrincipalPolicy failed for %s: %v", callerARN, err),
			Remediation: "Grant iam:SimulatePrincipalPolicy to run the preflight (or review required-permissions.md manually)",
		}}
	}

	var results []Result
	for _, ev := range out.EvaluationResults {
		action := aws.ToString(ev.EvalActionName)
		if ev.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			results = append(results, Result{Name: action, Severity: "ok", Status: true, Detail: "allowed"})
			continue
		}
		results = append(results, Result{
			Name: action, Severity: "error", Status: false,
			Detail:      fmt.Sprintf("%s for %s", string(ev.EvalDecision), callerARN),
			Remediation: "Grant " + action + " to the tpm principal (see required-permissions.md)",
		})
	}
	if len(results) == 0 {
		return []Result{{
			Name: "IAM permission self-check", Severity: "error", Status: false,
			Detail:      "simulator returned no evaluation results",
			Remediation: "Review required-permissions.md and the tpm principal's policy",
		}}
	}
	return results
}
