// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package goldenpcr

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeIMDS struct {
	body string
	err  error
}

func (f fakeIMDS) GetMetadata(context.Context, *imds.GetMetadataInput, ...func(*imds.Options)) (*imds.GetMetadataOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &imds.GetMetadataOutput{Content: io.NopCloser(strings.NewReader(f.body))}, nil
}

type fakeEC2 struct {
	images []ec2types.Image
	err    error
}

func (f fakeEC2) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeImagesOutput{Images: f.images}, nil
}

func tag(k, v string) ec2types.Tag { return ec2types.Tag{Key: aws.String(k), Value: aws.String(v)} }

func imageWith(tags ...ec2types.Tag) []ec2types.Image {
	return []ec2types.Image{{Tags: tags}}
}

func TestAMIIDFromIMDS(t *testing.T) {
	id, err := AMIIDFromIMDS(context.Background(), fakeIMDS{body: "ami-0abc123\n"})
	if err != nil {
		t.Fatalf("AMIIDFromIMDS: %v", err)
	}
	if id != "ami-0abc123" {
		t.Errorf("id = %q, want ami-0abc123 (trimmed)", id)
	}
}

func TestAMIIDFromIMDS_Rejects(t *testing.T) {
	if _, err := AMIIDFromIMDS(context.Background(), fakeIMDS{body: "not-an-ami"}); err == nil {
		t.Error("non-ami body: want error, got nil")
	}
	if _, err := AMIIDFromIMDS(context.Background(), fakeIMDS{err: errors.New("no route to IMDS")}); err == nil {
		t.Error("IMDS error: want error, got nil")
	}
}

func TestPCRTagsForImage(t *testing.T) {
	ec2c := fakeEC2{images: imageWith(
		tag("attest:pcr0", "ab12"),
		tag("attest:pcr7", "cd34"),
		tag("attest:vetted", "true"), // not a PCR tag — ignored
		tag("Name", "golden"),        // unrelated — ignored
	)}
	pcrs, err := PCRTagsForImage(context.Background(), ec2c, "ami-0abc123")
	if err != nil {
		t.Fatalf("PCRTagsForImage: %v", err)
	}
	if len(pcrs) != 2 {
		t.Fatalf("got %d PCRs, want 2: %v", len(pcrs), pcrs)
	}
	if pcrs["0"] != "ab12" || pcrs["7"] != "cd34" {
		t.Errorf("pcrs = %v, want {0:ab12, 7:cd34}", pcrs)
	}
}

func TestPCRTagsForImage_NoGoldenTags(t *testing.T) {
	pcrs, err := PCRTagsForImage(context.Background(), fakeEC2{images: imageWith(tag("Name", "x"))}, "ami-0abc")
	if err != nil {
		t.Fatalf("PCRTagsForImage: %v", err)
	}
	if len(pcrs) != 0 {
		t.Errorf("got %v, want empty map", pcrs)
	}
}

func TestPCRTagsForImage_Errors(t *testing.T) {
	cases := map[string]fakeEC2{
		"image not found":   {images: nil},
		"empty pcr value":   {images: imageWith(tag("attest:pcr0", ""))},
		"non-numeric index": {images: imageWith(tag("attest:pcrX", "ab"))},
		"describe error":    {err: errors.New("AccessDenied")},
	}
	for name, ec2c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PCRTagsForImage(context.Background(), ec2c, "ami-0abc"); err == nil {
				t.Errorf("%s: want error, got nil", name)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	md := fakeIMDS{body: "ami-0abc123"}
	ec2c := fakeEC2{images: imageWith(tag("attest:pcr0", "ab12"))}
	pcrs, err := Resolve(context.Background(), md, ec2c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pcrs["0"] != "ab12" {
		t.Errorf("pcrs = %v, want {0:ab12}", pcrs)
	}
}
