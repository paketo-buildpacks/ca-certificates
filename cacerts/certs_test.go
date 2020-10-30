package cacerts_test

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
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

	context("GenerateHashLinks", func() {
		var dir string

		it.Before(func() {
			var err error
			dir, err = ioutil.TempDir("", "hash-links-test")
			Expect(err).NotTo(HaveOccurred())
		})

		it.After(func() {
			Expect(os.RemoveAll(dir)).To(Succeed())
		})

		it("creates links in dir of format HHHHHHHH.D", func() {
			err := cacerts.GenerateHashLinks(dir, []string{
				filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"),
				filepath.Join("testdata", "SecureTrust_CA.pem"),
				filepath.Join("testdata", "SecureTrust_CA_Duplicate.pem"),
			})
			Expect(err).NotTo(HaveOccurred())
			fis, err := ioutil.ReadDir(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(fis)).To(Equal(3))

			Expect(fis[0].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err := os.Readlink(filepath.Join(dir, fis[0].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/Go_Daddy_Class_2_CA.pem"))
			Expect(fis[0].Name()).To(Equal("f081611a.0"))

			Expect(fis[1].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err = os.Readlink(filepath.Join(dir, fis[1].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/SecureTrust_CA.pem"))
			Expect(fis[1].Name()).To(Equal("f39fc864.0"))

			Expect(fis[2].Mode() & os.ModeType).To(Equal(os.ModeSymlink))
			target, err = os.Readlink(filepath.Join(dir, fis[2].Name()))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(Equal("testdata/SecureTrust_CA_Duplicate.pem"))
			Expect(fis[2].Name()).To(Equal("f39fc864.1"))
		})

		context("a cert file contains more than one cert", func() {
			it("returns an error", func() {
				path := filepath.Join("testdata", "multiple-certs.pem")
				err := cacerts.GenerateHashLinks(dir, []string{path})
				Expect(errors.Unwrap(err)).To(MatchError("found multiple PEM blocks, expected exactly one"))
			})
		})
	})

	context("SubjectNameHash", func() {
		it("matches openssl", func() {
			raw, err := ioutil.ReadFile(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"))
			Expect(err).NotTo(HaveOccurred())
			block, rest := pem.Decode(raw)
			Expect(rest).To(BeEmpty())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			hash, err := cacerts.SubjectNameHash(cert)
			Expect(err).NotTo(HaveOccurred())
			// openssl x509 -hash -in ./cacerts/testdata/Go_Daddy_Class_2_CA.pem -> f081611a
			Expect(hash).To(Equal(uint32(0xF081611A)))

			raw, err = ioutil.ReadFile(filepath.Join("testdata", "SecureTrust_CA.pem"))
			Expect(err).NotTo(HaveOccurred())
			block, rest = pem.Decode(raw)
			Expect(rest).To(BeEmpty())
			cert, err = x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			hash, err = cacerts.SubjectNameHash(cert)
			Expect(err).NotTo(HaveOccurred())
			// openssl x509 -hash -in ./cacerts/testdata/SecureTrust_CA.pem -> f39fc864
			Expect(hash).To(Equal(uint32(0xF39FC864)))
		})
	})

	context("CanonicalName", func() {
		context("cert contains non-UTF8String values", func() {
			var subject []byte
			it.Before(func() {
				raw, err := ioutil.ReadFile(filepath.Join("testdata", "Go_Daddy_Class_2_CA.pem"))
				Expect(err).NotTo(HaveOccurred())
				block, rest := pem.Decode(raw)
				Expect(rest).To(BeEmpty())
				cert, err := x509.ParseCertificate(block.Bytes)
				Expect(err).NotTo(HaveOccurred())

				var rdns rdnSeq
				subject = cert.RawSubject
				_, err = asn1.Unmarshal(subject, &rdns)
				Expect(err).NotTo(HaveOccurred())

				// Ensure we didn't start with UTF8 strings
				Expect(rdns[0][0].Value.Tag).NotTo(Equal(0xC)) // <-- tag 0xC identifies a UTF8 string
			})

			it("strips the leading sequence and converts all values to canonical UTF8Strings", func() {
				canonicalName, err := cacerts.CanonicalName(subject)
				Expect(err).NotTo(HaveOccurred())

				var set rdnSET

				rest, err := asn1.Unmarshal(canonicalName, &set)
				Expect(err).NotTo(HaveOccurred())       // <-- this would fail if sequence was not stripped
				Expect(set[0].Value.Tag).To(Equal(0xC)) // <-- ensure UTF8 encoding
				Expect(string(set[0].Value.Bytes)).To(Equal("us"))

				rest, err = asn1.Unmarshal(rest, &set)
				Expect(err).NotTo(HaveOccurred())
				Expect(set[0].Value.Tag).To(Equal(0xC))
				Expect(string(set[0].Value.Bytes)).To(Equal("the go daddy group, inc."))

				rest, err = asn1.Unmarshal(rest, &set)
				Expect(err).NotTo(HaveOccurred())
				Expect(set[0].Value.Tag).To(Equal(0xC))
				Expect(string(set[0].Value.Bytes)).To(Equal("go daddy class 2 certification authority"))

				Expect(rest).To(BeEmpty())
			})
		})
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

type rdnSeq []rdnSET

type rdnSET []atv

type atv struct {
	OIDC  asn1.ObjectIdentifier
	Value asn1.RawValue
}
