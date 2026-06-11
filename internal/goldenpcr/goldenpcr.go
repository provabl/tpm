// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package goldenpcr resolves the golden boot-measurement PCRs recorded on this
// instance's source AMI — the attest:pcr<N> tags vet's `ami-reference` writes —
// so `nitro attest --expected-from-ami` can feed them to the expected_pcr<N>
// appraiser check without the operator hand-copying hex at launch.
//
// The tags are locked to the vetter principal by ground's lockdown SCP, so a
// running instance cannot rewrite its own golden reference. Reading them is the
// consumption half of the runtime image binding (provabl#13).
package goldenpcr

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// TagPCRPrefix is the AMI-tag key prefix vet writes (attest:pcr0, attest:pcr7, …).
// Kept in lockstep with vet's internal/amitag.TagPCRPrefix and ground's lockdown SCP.
const TagPCRPrefix = "attest:pcr"

// MetadataClient reads instance metadata. Satisfied by the ec2/imds client in
// production; faked in tests.
type MetadataClient interface {
	GetMetadata(context.Context, *imds.GetMetadataInput, ...func(*imds.Options)) (*imds.GetMetadataOutput, error)
}

// ImageDescriber reads AMI attributes. Satisfied by the ec2 client in production;
// faked in tests.
type ImageDescriber interface {
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
}

// AMIIDFromIMDS reads this instance's source AMI id from the instance metadata
// service ("ami-id"). Only meaningful when run on the live instance.
func AMIIDFromIMDS(ctx context.Context, md MetadataClient) (string, error) {
	out, err := md.GetMetadata(ctx, &imds.GetMetadataInput{Path: "ami-id"})
	if err != nil {
		return "", fmt.Errorf("read ami-id from IMDS (is this running on the instance?): %w", err)
	}
	defer out.Content.Close()
	b, err := io.ReadAll(out.Content)
	if err != nil {
		return "", fmt.Errorf("read IMDS ami-id body: %w", err)
	}
	id := strings.TrimSpace(string(b))
	if !strings.HasPrefix(id, "ami-") {
		return "", fmt.Errorf("IMDS returned %q, not an AMI id", id)
	}
	return id, nil
}

// PCRTagsForImage reads amiID's tags and returns the golden PCRs keyed by index
// ("0","7" → hex), stripped of the attest:pcr prefix — the shape the
// expected_pcr<N> appraiser params want. A non-numeric index suffix or a tag
// missing a value is an error (a malformed golden reference must not silently
// degrade to an unenforced check). Returns an empty map if the AMI carries no
// attest:pcr* tags.
func PCRTagsForImage(ctx context.Context, ec2c ImageDescriber, amiID string) (map[string]string, error) {
	out, err := ec2c.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{amiID}})
	if err != nil {
		return nil, fmt.Errorf("describe image %s: %w", amiID, err)
	}
	if len(out.Images) == 0 {
		return nil, fmt.Errorf("image %s not found (or not visible to this principal)", amiID)
	}
	pcrs := map[string]string{}
	for _, tag := range out.Images[0].Tags {
		key := derefTag(tag.Key)
		if !strings.HasPrefix(key, TagPCRPrefix) {
			continue
		}
		idx := strings.TrimPrefix(key, TagPCRPrefix)
		if _, err := strconv.Atoi(idx); err != nil {
			return nil, fmt.Errorf("malformed golden-PCR tag %q on %s: index must be numeric", key, amiID)
		}
		val := derefTag(tag.Value)
		if val == "" {
			return nil, fmt.Errorf("golden-PCR tag %q on %s has an empty value", key, amiID)
		}
		pcrs[idx] = val
	}
	return pcrs, nil
}

// Resolve wires the live IMDS + EC2 clients: reads this instance's source AMI id,
// then returns its golden-PCR tags. Used by `--expected-from-ami` on the instance.
func Resolve(ctx context.Context, md MetadataClient, ec2c ImageDescriber) (map[string]string, error) {
	amiID, err := AMIIDFromIMDS(ctx, md)
	if err != nil {
		return nil, err
	}
	return PCRTagsForImage(ctx, ec2c, amiID)
}

func derefTag(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
