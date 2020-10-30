package cacerts_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/buildpacks/libcnb"
	. "github.com/onsi/gomega"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func testLayer(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect    = NewWithT(t).Expect
		layerPath string
	)

	it.Before(func() {
		var err error

		layerPath, err = ioutil.TempDir("", "distribution-layers")
		Expect(err).NotTo(HaveOccurred())
	})

	it.After(func() {
		Expect(os.RemoveAll(layerPath)).To(Succeed())
	})

	context("Contribute", func() {
		var certPaths []string

		it.Before(func() {
			certPaths = []string{
				filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"),
				filepath.Join("testdata", "SecureTrust_CA.pem"),
				filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem"),
			}
		})

		it("appends to SSL_CERT_DIR", func() {
			contributor := cacerts.NewLayer(certPaths)
			layer, err := contributor.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			certsDir := filepath.Join(layerPath, "certs")
			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.append"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.append"]).
				To(Equal(certsDir))
			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_DIR.delim"))
			Expect(layer.BuildEnvironment["SSL_CERT_DIR.delim"]).To(Equal(":"))
		})

		it("sets SSL_CERT_FILE to stack default", func() {
			contributor := cacerts.NewLayer(certPaths)
			layer, err := contributor.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			Expect(layer.BuildEnvironment).To(HaveKey("SSL_CERT_FILE.default"))
			Expect(layer.BuildEnvironment["SSL_CERT_FILE.default"]).
				To(Equal("/etc/ssl/certs/ca-certificates.crt"))
		})

		it("creates certificate symlinks in SSL_CERT_DIR", func() {
			contributor := cacerts.NewLayer(certPaths)
			_, err := contributor.Contribute(libcnb.Layer{Path: layerPath})
			Expect(err).NotTo(HaveOccurred())

			certsDir := filepath.Join(layerPath, "certs")
			fis, err := ioutil.ReadDir(certsDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(fis)).To(Equal(3))

			Expect(fis[0].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err := os.Readlink(filepath.Join(certsDir, fis[0].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/Go_Daddy_Class_2_CA.pem"))
			Expect(fis[0].Name()).To(Equal("f081611a.0"))

			Expect(fis[1].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err = os.Readlink(filepath.Join(certsDir, fis[1].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/SecureTrust_CA.pem"))
			Expect(fis[1].Name()).To(Equal("f39fc864.0"))

			Expect(fis[2].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err = os.Readlink(filepath.Join(certsDir, fis[2].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/SecureTrust_CA_Duplicate.pem"))
			Expect(fis[2].Name()).To(Equal("f39fc864.1"))
		})
	})
}
