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

func testExecD(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect

		execd     *cacerts.ExecD
		env       map[string]string
		certDir   string
		certPaths []string
		called    int
	)

	it.Before(func() {
		env = map[string]string{}
		execd = &cacerts.ExecD{
			GenerateHashLinks: func(dir string, paths []string) error {
				certDir = dir
				certPaths = paths
				called++
				return nil
			},
			GetEnv: func(k string) string {
				return env[k]
			},
		}
	})

	context("Binding exists with type ca-certificates", func() {
		it.Before(func() {
			execd.Bindings = []libcnb.Binding{
				{
					Type: "ca-certificates",
					Path: "testdata",
					Secret: map[string]string{
						"SecureTrust_CA.pem":           "",
						"SecureTrust_CA_Duplicate.pem": "",
					},
				},
				{
					Type: "ca-certificates",
					Path: "testdata",
					Secret: map[string]string{
						"Go_Daddy_Class_2_CA.pem": "",
					},
				},
			}
		})

		context("SSL_CERT_FILE is unset", func() {
			it("sets it to the stack default", func() {
				envFile, err := execd.Execute()
				Expect(err).NotTo(HaveOccurred())
				Expect(called).To(Equal(1))
				Expect(envFile["SSL_CERT_FILE"]).To(Equal(cacerts.DefaultCAFile))
			})
		})

		context("SSL_CERT_FILE is set", func() {
			it.Before(func() {
				env["SSL_CERT_FILE"] = "some-file"
			})

			it("does not override SSL_CERT_FILE", func() {
				envFile, err := execd.Execute()
				Expect(err).NotTo(HaveOccurred())
				Expect(called).To(Equal(1))
				Expect(envFile).NotTo(HaveKey("SSL_CERT_FILE"))
			})
		})

		context("SSL_CERT_DIR is unset", func() {
			it("sets SSL_CERT_DIR to a dir containing hash links", func() {
				envFile, err := execd.Execute()
				Expect(err).NotTo(HaveOccurred())
				Expect(called).To(Equal(1))
				Expect(certPaths).To(ConsistOf(
					ContainSubstring(filepath.Join("testdata", "SecureTrust_CA.pem")),
					ContainSubstring(filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem")),
					ContainSubstring(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem")),
				))
				Expect(envFile["SSL_CERT_DIR"]).To(Equal(certDir))
			})
		})

		context("SSL_CERT_DIR is set", func() {
			it.Before(func() {
				env["SSL_CERT_DIR"] = "some-dir"
			})

			it("appends to SSL_CERT_DIR a dir containing hash links", func() {
				envFile, err := execd.Execute()
				Expect(err).NotTo(HaveOccurred())
				Expect(certPaths).To(ConsistOf(
					ContainSubstring(filepath.Join("testdata", "SecureTrust_CA.pem")),
					ContainSubstring(filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem")),
					ContainSubstring(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem")),
				))
				Expect(envFile["SSL_CERT_DIR"]).To(Equal("some-dir" + string(os.PathListSeparator) + certDir))
			})
		})
	})

	context("Binding does not exist with type ca-certificates", func() {
		it("does nothing", func() {
			env, err := execd.Execute()
			Expect(err).NotTo(HaveOccurred())
			Expect(env).To(BeEmpty())
		})
	})
}
