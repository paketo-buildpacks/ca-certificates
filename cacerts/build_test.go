/*
 * Copyright 2018-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

	context("plan includes ca-certificates entry", func() {
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
			contributor, ok := result.Layers[0].(*cacerts.TrustedCAs)
			Expect(ok).To(BeTrue())
			Expect(len(contributor.CertPaths)).To(Equal(3))
			Expect(contributor.CertPaths).To(ConsistOf([]string{
				"some/path/cert1.pem",
				"some/path/cert2.pem",
				"some/path/cert3.pem",
			}))
		})
	})

	context("plan includes multiple ca-certificates entries", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{
					Name: "ca-certificates",
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							"some/path/cert1.pem",
							"some/path/cert3.pem",
						},
					},
				},
				{
					Name: "ca-certificates",
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							"some/path/cert2.pem",
						},
					},
				},
			}
			var err error
			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("contributes a single ca-certificates", func() {
			Expect(len(result.Layers)).To(BeNumerically(">=", 1))
			Expect(result.Layers[0].Name()).To(Equal("ca-certificates"))
			contributor, ok := result.Layers[0].(*cacerts.TrustedCAs)
			Expect(ok).To(BeTrue())
			Expect(len(contributor.CertPaths)).To(Equal(3))
			Expect(contributor.CertPaths).To(Equal([]string{
				"some/path/cert1.pem",
				"some/path/cert2.pem",
				"some/path/cert3.pem",
			}))
		})
	})

	context("plan include ca-cert-helper entry", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{Name: "ca-cert-helper"},
			}
			var err error
			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("contributes helper", func() {
			Expect(len(result.Layers)).To(Equal(1))
			helperLayer, ok := result.Layers[0].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
		})
	})

	context("plan includes multiple ca-cert-helper entries", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{Name: "ca-cert-helper"},
				{Name: "ca-cert-helper"},
			}
			var err error
			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("contributes helper", func() {
			Expect(len(result.Layers)).To(Equal(1))
			helperLayer, ok := result.Layers[0].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
		})
	})

	context("plan includes unrecognized entry", func() {
		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{Name: "unexpected-entry"},
			}
		})

		it("returns an error", func() {
			_, err := build.Build(ctx)
			Expect(err).To(MatchError(`received unexpected buildpack plan entry "unexpected-entry"`))
		})
	})
}
