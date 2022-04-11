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
	"os"
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/v3/cacerts"
)

func testDetect(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		ctx    libcnb.DetectContext
		detect cacerts.Detect
	)

	it.Before(func() {
		ctx.Platform.Environment = map[string]string{}
	})

	context("Binding exists with type ca-certificates", func() {
		var result libcnb.DetectResult
		it.Before(func() {
			ctx.Platform.Bindings = []libcnb.Binding{
				{
					Type: cacerts.BindingType,
					Path: "some-path",
					Secret: map[string]string{
						"cert1.pem": "",
						"cert2.pem": "",
					},
				},
				{
					Type: cacerts.BindingType,
					Path: "other-path",
					Secret: map[string]string{
						"cert3.pem": "",
					},
				},
			}
			var err error
			result, err = detect.Detect(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("detect passes", func() {
			Expect(result.Pass).To(BeTrue())
		})

		it("first plan provides and requires ca-certificate", func() {
			Expect(len(result.Plans)).To(BeNumerically(">=", 1))
			Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
				Provides: []libcnb.BuildPlanProvide{
					{Name: cacerts.PlanEntryCACerts},
					{Name: cacerts.PlanEntryCACertsHelper},
				},
				Requires: []libcnb.BuildPlanRequire{
					{
						Name: cacerts.PlanEntryCACerts,
						Metadata: map[string]interface{}{
							"paths": []string{
								filepath.Join("other-path", "cert3.pem"),
								filepath.Join("some-path", "cert1.pem"),
								filepath.Join("some-path", "cert2.pem"),
							},
						},
					},
					{Name: cacerts.PlanEntryCACertsHelper},
				},
			}))
		})

		context("BP_ENABLE_RUNTIME_CERT_BINDING is set to false", func() {
			var result libcnb.DetectResult
			it.Before(func() {
				os.Setenv("BP_ENABLE_RUNTIME_CERT_BINDING", "false")

				var err error
				result, err = detect.Detect(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			it.After(func() {
				os.Unsetenv("BP_ENABLE_RUNTIME_CERT_BINDING")
			})

			it("detect passes", func() {
				Expect(result.Pass).To(BeTrue())
			})

			it("there is no ca-certificates-helper plan entry", func() {
				Expect(len(result.Plans)).To(Equal(1))

				Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
					Provides: []libcnb.BuildPlanProvide{
						{Name: cacerts.PlanEntryCACerts},
					},
					Requires: []libcnb.BuildPlanRequire{
						{
							Name: cacerts.PlanEntryCACerts,
							Metadata: map[string]interface{}{
								"paths": []string{
									filepath.Join("other-path", "cert3.pem"),
									filepath.Join("some-path", "cert1.pem"),
									filepath.Join("some-path", "cert2.pem"),
								},
							},
						},
					},
				}))
			})
		})

		context("BP_RUNTIME_CERT_BINDING_DISABLED is set to true", func() {
			var result libcnb.DetectResult
			it.Before(func() {
				os.Setenv("BP_RUNTIME_CERT_BINDING_DISABLED", "true")

				var err error
				result, err = detect.Detect(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			it.After(func() {
				os.Unsetenv("BP_RUNTIME_CERT_BINDING_DISABLED")
			})

			it("detect passes", func() {
				Expect(result.Pass).To(BeTrue())
			})

			it("there is no ca-certificates-helper plan entry", func() {
				Expect(len(result.Plans)).To(Equal(1))

				Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
					Provides: []libcnb.BuildPlanProvide{
						{Name: cacerts.PlanEntryCACerts},
					},
					Requires: []libcnb.BuildPlanRequire{
						{
							Name: cacerts.PlanEntryCACerts,
							Metadata: map[string]interface{}{
								"paths": []string{
									filepath.Join("other-path", "cert3.pem"),
									filepath.Join("some-path", "cert1.pem"),
									filepath.Join("some-path", "cert2.pem"),
								},
							},
						},
					},
				}))
			})
		})
	})

	context("Binding does not exist with type ca-certificates", func() {
		var result libcnb.DetectResult
		it.Before(func() {
			var err error
			result, err = detect.Detect(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		it("detect passes", func() {
			Expect(result.Pass).To(BeTrue())
		})

		it("first plan provides ca-certificates", func() {
			Expect(len(result.Plans)).To(BeNumerically(">=", 1))
			Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
				Provides: []libcnb.BuildPlanProvide{
					{Name: cacerts.PlanEntryCACerts},
					{Name: cacerts.PlanEntryCACertsHelper},
				},
				Requires: []libcnb.BuildPlanRequire{
					{Name: cacerts.PlanEntryCACertsHelper},
				},
			}))
		})

		it("second plan always contributes the ca-certs-helper", func() {
			Expect(len(result.Plans)).To(Equal(2))
			Expect(result.Plans[1]).To(Equal(libcnb.BuildPlan{
				Provides: []libcnb.BuildPlanProvide{
					{Name: cacerts.PlanEntryCACertsHelper},
				},
				Requires: []libcnb.BuildPlanRequire{
					{Name: cacerts.PlanEntryCACertsHelper},
				},
			}))
		})

		context("BP_ENABLE_RUNTIME_CERT_BINDING is set to false", func() {
			var result libcnb.DetectResult
			it.Before(func() {
				os.Setenv("BP_ENABLE_RUNTIME_CERT_BINDING", "false")

				var err error
				result, err = detect.Detect(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			it.After(func() {
				os.Unsetenv("BP_ENABLE_RUNTIME_CERT_BINDING")
			})

			it("detect passes", func() {
				Expect(result.Pass).To(BeTrue())
			})

			it("first plan does not require ca-certificates", func() {
				Expect(len(result.Plans)).To(Equal(1))
				Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
					Provides: []libcnb.BuildPlanProvide{
						{Name: cacerts.PlanEntryCACerts},
					},
					Requires: []libcnb.BuildPlanRequire{},
				}))
			})
		})

		context("BP_RUNTIME_CERT_BINDING_DISABLED is set to true", func() {
			var result libcnb.DetectResult
			it.Before(func() {
				os.Setenv("BP_RUNTIME_CERT_BINDING_DISABLED", "true")

				var err error
				result, err = detect.Detect(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			it.After(func() {
				os.Unsetenv("BP_RUNTIME_CERT_BINDING_DISABLED")
			})

			it("detect passes", func() {
				Expect(result.Pass).To(BeTrue())
			})

			it("first plan does not require ca-certificates", func() {
				Expect(len(result.Plans)).To(Equal(1))
				Expect(result.Plans[0]).To(Equal(libcnb.BuildPlan{
					Provides: []libcnb.BuildPlanProvide{
						{Name: cacerts.PlanEntryCACerts},
					},
					Requires: []libcnb.BuildPlanRequire{},
				}))
			})
		})
	})
}
