package cacerts_test

import (
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sclevine/spec"

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func testCerts(t *testing.T, context spec.G, it spec.S) {
	var (
		Expect = NewWithT(t).Expect
	)

	context("SubjectNameHash", func() {
		it("matches openssl", func() {
			cert, err := ioutil.ReadFile(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"))
			Expect(err).NotTo(HaveOccurred())
			block, rest := pem.Decode(cert)
			Expect(rest).To(BeEmpty())
			hash, err := cacerts.SubjectNameHash(block)
			Expect(err).NotTo(HaveOccurred())
			// openssl x509 -hash -in ./cacerts/testdata/Go_Daddy_Class_2_CA.pem -> f081611a
			Expect(hash).To(Equal(uint32(0xF081611A)))

			cert, err = ioutil.ReadFile(filepath.Join("testdata", "SecureTrust_CA.pem"))
			Expect(err).NotTo(HaveOccurred())
			block, rest = pem.Decode(cert)
			Expect(rest).To(BeEmpty())
			hash, err = cacerts.SubjectNameHash(block)
			Expect(err).NotTo(HaveOccurred())
			// openssl x509 -hash -in ./cacerts/testdata/SecureTrust_CA.pem -> f39fc864
			Expect(hash).To(Equal(uint32(0xF39FC864)))
		})
	})

	context("CanonicalName", func() {

	})

	context("CanonicalString", func() {
		it("trims leading and trailing whitespace", func() {
			Expect(cacerts.CanonicalString(" some-val ")).To(Equal("some-val"))
			Expect(cacerts.CanonicalString("\f\tsome-val\n\n\v")).To(Equal("some-val"))
		})

		it("replaces any remaining whitespace with a single ' '", func() {
			Expect(cacerts.CanonicalString("SOME  VAL")).To(Equal("some val"))
			Expect(cacerts.CanonicalString("SOME\nVAL")).To(Equal("some val"))
			Expect(cacerts.CanonicalString("SOME \f\t\n\r\vVAL")).To(Equal("some val"))
		})

		it(`defines whitespaces as '\f' '\t' '\n' '\r'  and '\v' runes`, func() {
			// unicode U+0085 (NEL) is not trimmed
			Expect(cacerts.CanonicalString("\u0085some-val\u0085")).To(Equal("\u0085some-val\u0085"))
			// unicode U+00A0 (NBSP) is not trimmed
			Expect(cacerts.CanonicalString("\u00A0some-val\u00A0")).To(Equal("\u00A0some-val\u00A0"))
		})

		it("converts to lowercase", func() {
			Expect(cacerts.CanonicalString("SOME VAL")).To(Equal("some val"))
		})
	})
}
