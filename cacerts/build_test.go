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
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/paketo-buildpacks/libpak"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/v3/cacerts"
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
					Name: cacerts.PlanEntryCACerts,
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							filepath.Join("testdata", "SecureTrust_CA.pem"),
							filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem"),
							filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"),
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
			contributor, ok := result.Layers[0].(*cacerts.TrustedCACerts)
			Expect(ok).To(BeTrue())
			Expect(len(contributor.CertPaths)).To(Equal(3))
			Expect(contributor.CertPaths).To(ConsistOf(
				ContainSubstring(filepath.Join("testdata", "SecureTrust_CA.pem")),
				ContainSubstring(filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem")),
				ContainSubstring(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem")),
			))
		})
	})

	context("plan includes multiple ca-certificates entries", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{
					Name: cacerts.PlanEntryCACerts,
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							filepath.Join("testdata", "SecureTrust_CA.pem"),
							filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"),
						},
					},
				},
				{
					Name: cacerts.PlanEntryCACerts,
					Metadata: map[string]interface{}{
						"paths": []interface{}{
							filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem"),
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
			contributor, ok := result.Layers[0].(*cacerts.TrustedCACerts)
			Expect(ok).To(BeTrue())
			Expect(len(contributor.CertPaths)).To(Equal(3))
			Expect(contributor.CertPaths).To(ConsistOf(
				ContainSubstring(filepath.Join("testdata", "SecureTrust_CA.pem")),
				ContainSubstring(filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem")),
				ContainSubstring(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem")),
			))
		})
	})

	context("plan include ca-cert-helper entry", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{Name: cacerts.PlanEntryCACertsHelper},
			}

		})

		it("contributes helper for API <= 0.6", func() {

			var err error
			ctx.Buildpack.API = "0.6"

			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Layers)).To(Equal(1))
			helperLayer, ok := result.Layers[0].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
			Expect(len(result.BOM.Entries)).To(Equal(1))
			Expect(result.BOM.Entries[0].Name).To(Equal("helper"))
		})
		it("contributes helper for API 0.7+", func() {
			var err error
			ctx.Buildpack.API = "0.7"

			result, err = build.Build(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(len(result.Layers)).To(Equal(1))
			helperLayer, ok := result.Layers[0].(libpak.HelperLayerContributor)
			Expect(ok).To(BeTrue())
			Expect(helperLayer.Name()).To(Equal("helper"))
			Expect(len(result.BOM.Entries)).To(Equal(1))
		})
	})

	context("plan includes multiple ca-cert-helper entries", func() {
		var result libcnb.BuildResult

		it.Before(func() {
			ctx.Plan.Entries = []libcnb.BuildpackPlanEntry{
				{Name: cacerts.PlanEntryCACertsHelper},
				{Name: cacerts.PlanEntryCACertsHelper},
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
