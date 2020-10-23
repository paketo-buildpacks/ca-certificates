package cacerts_test

import (
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func testDetect(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		ctx    libcnb.DetectContext
		detect cacerts.Detect
	)

	it.Before(func() {
		ctx.Platform.Environment = map[string]string{}
		ctx.Buildpack.Metadata = map[string]interface{}{
			"configurations": []map[string]interface{}{
				{
					"name":    "BP_RUNTIME_CACERTS_ENABLED",
					"default": "true",
				},
			},
		}
	})

	context("Binding exists with type ca-certificates", func() {
		it.Before(func() {
			ctx.Platform.Bindings = []libcnb.Binding{
				{
					Type: "ca-certificates",
					Path: "some-path",
					Secret: map[string]string{
						"cert1.pem": "",
						"cert2.pem": "",
					},
				},
				{
					Type: "ca-certificates",
					Path: "other-path",
					Secret: map[string]string{
						"cert3.pem": "",
					},
				},
			}
		})

		it("provides and requires ca-certificates", func() {
			Expect(detect.Detect(ctx)).To(Equal(libcnb.DetectResult{
				Pass: true,
				Plans: []libcnb.BuildPlan{
					{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "ca-certificates"},
						},
						Requires: []libcnb.BuildPlanRequire{
							{
								Name: "ca-certificates",
								Metadata: map[string]interface{}{
									"paths": []string{
										filepath.Join("other-path", "cert3.pem"),
										filepath.Join("some-path", "cert1.pem"),
										filepath.Join("some-path", "cert2.pem"),
									},
								},
							},
						},
					},
				},
			}))
		})
	})

	context("Binding does not exist with type ca-certificates", func() {
		it("optionally provides ca-certificates", func() {
			Expect(detect.Detect(ctx)).To(Equal(libcnb.DetectResult{
				Pass: true,
				Plans: []libcnb.BuildPlan{
					{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "ca-certificates"},
						},
					},
					{}, // always contributes helper
				},
			}))
		})
	})
}
