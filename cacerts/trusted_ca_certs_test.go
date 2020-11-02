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

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func testTrustedCACerts(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect     = NewWithT(t).Expect
		layerPath  string
		trustedCAs *cacerts.TrustedCACerts

		certDir   string
		certPaths []string
		called    int
	)

	it.Before(func() {
		var err error

		layerPath, err = ioutil.TempDir("", "distribution-layers")
		Expect(err).NotTo(HaveOccurred())
		trustedCAs = &cacerts.TrustedCACerts{
			LayerContributor: libpak.NewLayerContributor("CA Certificates", map[string]interface{}{}),
			GenerateHashLinks: func(dir string, paths []string) error {
				certDir = dir
				certPaths = paths
				called++
				return nil
			},
		}
	})

	it.After(func() {
		Expect(os.RemoveAll(layerPath)).To(Succeed())
	})

	context("Contribute", func() {
		it.Before(func() {
			trustedCAs.CertPaths = []string{
				filepath.Join("other-path", "cert3.pem"),
				filepath.Join("some-path", "cert1.pem"),
				filepath.Join("some-path", "cert2.pem"),
			}
		})

		it("appends to SSL_CERT_DIR", func() {
			layer, err := trustedCAs.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.append"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.append"]).
				To(Equal(filepath.Join(layerPath, "ca-certificates")))
			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.delim"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.delim"]).To(Equal(":"))
		})

		it("sets SSL_CERT_FILE to stack default", func() {
			layer, err := trustedCAs.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_FILE.default"))
			Expect(layer.BuildEnvironment["SSL_CERT_FILE.default"]).
				To(Equal("/etc/ssl/certs/ca-certificates.crt"))
		})

		it("creates certificate symlinks in SSL_CERT_DIR", func() {
			_, err := trustedCAs.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			Expect(called).To(Equal(1))
			Expect(certPaths).To(Equal([]string{
				filepath.Join("other-path", "cert3.pem"),
				filepath.Join("some-path", "cert1.pem"),
				filepath.Join("some-path", "cert2.pem"),
			}))
			Expect(certDir).To(Equal(filepath.Join(layerPath, "ca-certificates")))
		})
	})
}
