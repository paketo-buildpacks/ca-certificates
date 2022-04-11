/*
 * Copyright 2018-2022 the original author or authors.
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
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/v3/cacerts"
)

func testTrustedCACerts(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect     = NewWithT(t).Expect
		layer      libcnb.Layer
		certsDir   string
		layerDir   string
		trustedCAs *cacerts.TrustedCACerts

		caCertsList []string
		certDir     string
		certPaths   []string
		called      int

		generateHashLinks func(dir string, paths []string) error
	)

	it.Before(func() {
		var err error

		certsDir, err = ioutil.TempDir("", "ca-cert-files")
		Expect(err).NotTo(HaveOccurred())

		layerDir, err = ioutil.TempDir("", "ca-certs-layer")
		Expect(err).NotTo(HaveOccurred())

		layers := &libcnb.Layers{Path: layerDir}
		layer, err = layers.Layer("test-layer")
		Expect(err).NotTo(HaveOccurred())

		generateHashLinks = func(dir string, paths []string) error {
			certDir = dir
			certPaths = paths
			called++
			return nil
		}

		caCertsList = []string{
			filepath.Join(certsDir, "other-path", "cert3.pem"),
			filepath.Join(certsDir, "some-path", "cert1.pem"),
			filepath.Join(certsDir, "some-path", "cert2.pem"),
		}

		for _, caCert := range caCertsList {
			Expect(os.MkdirAll(filepath.Dir(caCert), 0755)).ToNot(HaveOccurred())
			Expect(ioutil.WriteFile(caCert, []byte{}, 0644)).ToNot(HaveOccurred())
		}

		trustedCAs = cacerts.NewTrustedCACerts(caCertsList, false)
		trustedCAs.GenerateHashLinks = generateHashLinks
	})

	it.After(func() {
		Expect(os.RemoveAll(layerDir)).To(Succeed())
	})

	context("Contribute", func() {
		it("appends to SSL_CERT_DIR", func() {
			layer, err := trustedCAs.Contribute(layer)
			Expect(err).NotTo(HaveOccurred())

			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.append"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.append"]).
				To(Equal(filepath.Join(layer.Path, "ca-certificates")))
			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.delim"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.delim"]).To(Equal(":"))
			Expect(layer.LaunchEnvironment).To(BeEmpty())
		})

		it("sets SSL_CERT_FILE to stack default", func() {
			layer, err := trustedCAs.Contribute(layer)
			Expect(err).NotTo(HaveOccurred())

			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_FILE.default"))
			Expect(layer.BuildEnvironment["SSL_CERT_FILE.default"]).
				To(Equal("/etc/ssl/certs/ca-certificates.crt"))
			Expect(layer.LaunchEnvironment).To(BeEmpty())
		})

		it("creates certificate symlinks in SSL_CERT_DIR", func() {
			_, err := trustedCAs.Contribute(layer)
			Expect(err).NotTo(HaveOccurred())

			Expect(called).To(Equal(1))
			Expect(certPaths).To(Equal([]string{
				filepath.Join(certsDir, "other-path", "cert3.pem"),
				filepath.Join(certsDir, "some-path", "cert1.pem"),
				filepath.Join(certsDir, "some-path", "cert2.pem"),
			}))
			Expect(certDir).To(Equal(filepath.Join(layer.Path, "ca-certificates")))
		})

		context("embed certs at launch", func() {
			it.Before(func() {
				trustedCAs = cacerts.NewTrustedCACerts(caCertsList, true)
				trustedCAs.GenerateHashLinks = generateHashLinks
			})

			it("copies ca-certs", func() {
				layer, err := trustedCAs.Contribute(layer)
				Expect(err).NotTo(HaveOccurred())

				for _, caCert := range caCertsList {
					Expect(filepath.Join(layer.Path, "embedded-certs", filepath.Base(caCert))).To(BeARegularFile())
				}
			})

			it("appends to SSL_CERT_DIR", func() {
				layer, err := trustedCAs.Contribute(layer)
				Expect(err).NotTo(HaveOccurred())

				Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.append"))
				Expect(layer.BuildEnvironment["SSL_CERT_DIR.append"]).
					To(Equal(filepath.Join(layer.Path, "ca-certificates")))
				Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.delim"))
				Expect(layer.BuildEnvironment["SSL_CERT_DIR.delim"]).To(Equal(":"))

				Expect(layer.LaunchEnvironment).To(HaveKey("SSL_CERT_DIR.append"))
				Expect(layer.LaunchEnvironment["SSL_CERT_DIR.append"]).
					To(Equal(filepath.Join(layer.Path, "ca-certificates")))
				Expect(layer.LaunchEnvironment).To(HaveKey("SSL_CERT_DIR.delim"))
				Expect(layer.LaunchEnvironment["SSL_CERT_DIR.delim"]).To(Equal(":"))
			})

			it("sets SSL_CERT_FILE to stack default", func() {
				layer, err := trustedCAs.Contribute(layer)
				Expect(err).NotTo(HaveOccurred())

				Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_FILE.default"))
				Expect(layer.BuildEnvironment["SSL_CERT_FILE.default"]).
					To(Equal("/etc/ssl/certs/ca-certificates.crt"))

				Expect(layer.LaunchEnvironment).To(HaveKey("SSL_CERT_FILE.default"))
				Expect(layer.LaunchEnvironment["SSL_CERT_FILE.default"]).
					To(Equal("/etc/ssl/certs/ca-certificates.crt"))
			})
		})
	})
}
