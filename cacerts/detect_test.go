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

		it("provides and requires ca-certificates and ca-cert-helper", func() {
			Expect(detect.Detect(ctx)).To(Equal(libcnb.DetectResult{
				Pass: true,
				Plans: []libcnb.BuildPlan{
					{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "ca-certificates"},
							{Name: "ca-cert-helper"},
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
							{Name: "ca-cert-helper"},
						},
					},
				},
			}))
		})
	})

	context("Binding does not exist with type ca-certificates", func() {
		it("provides ca-certificates and provides and requires ca-cert-helper", func() {
			Expect(detect.Detect(ctx)).To(Equal(libcnb.DetectResult{
				Pass: true,
				Plans: []libcnb.BuildPlan{
					{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "ca-certificates"},
							{Name: "ca-cert-helper"},
						},
						Requires: []libcnb.BuildPlanRequire{
							{Name: "ca-cert-helper"},
						},
					},
					{
						Provides: []libcnb.BuildPlanProvide{
							{Name: "ca-cert-helper"},
						},
						Requires: []libcnb.BuildPlanRequire{
							{Name: "ca-cert-helper"},
						},
					},
				},
			}))
		})
	})
}
