package cacerts_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/libpak"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func testBuild(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		ctx   libcnb.BuildContext
		build cacerts.Build
	)

	it.Before(func() {
		var err error
		ctx.Layers.Path, err = ioutil.TempDir("", "build-layers")
		Expect(err).NotTo(HaveOccurred())

		build = cacerts.Build{}
	})

	it.After(func() {
		Expect(os.RemoveAll(ctx.Layers.Path)).To(Succeed())
	})

	context("plan does not include ca-certificates", func() {
		it("contributes helper layer", func() {
			result, err := build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.Layers).To(HaveLen(1))
			helperLayer, ok := result.Layers[0].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
		})
	})

	context("plan includes ca-certificates", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{
					Name: "ca-certificates",
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							"some/path/cert1.pem",
							"some/path/cert2.pem",
							"some/path/cert3.pem",
						},
					},
				},
			}
			var err error
			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("contributes a ca-certificates layers", func() {
			Expect(len(result.Layers)).To(BeNumerically(">=", 1))
			Expect(result.Layers[0].Name()).To(Equal("ca-certificates"))
			contributor, ok := result.Layers[0].(*cacerts.Layer)
			Expect(ok).To(BeTrue())
			Expect(len(contributor.CertPaths)).To(Equal(3))
			Expect(contributor.CertPaths).To(ConsistOf([]string{
				"some/path/cert1.pem",
				"some/path/cert2.pem",
				"some/path/cert3.pem",
			}))
		})

		it("contributes helper layer", func() {
			Expect(len(result.Layers)).To(Equal(2))
			helperLayer, ok := result.Layers[1].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
		})
	})
}
