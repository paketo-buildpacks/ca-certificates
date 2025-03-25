/*
 * Copyright 2018-2024 the original author or authors.
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

package cacerts

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Environment variables and defaults used by openssl to load trusted CA certificates
// (see https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_verify_paths.html)
const (
	// EnvCAPath is the environment variable that can be used to set CApath
	EnvCAPath string = "SSL_CERT_DIR"
	// EnvCAFile is the environment variable that can be used to set CAfile
	EnvCAFile string = "SSL_CERT_FILE"

	// DefaultCAFile provides the default CAfile on ubuntu
	DefaultCAFile string = "/etc/ssl/certs/ca-certificates.crt"
)

// GenerateHashLinks generates symlinks the given directory point to the given certificates paths.
// The name of each symlink file will be of the format HHHHHHHH.D where HHHHHHHH is the 8 character
// hexidecimal representation of the SubjectNameHash. D shall be the integer '0' unless there is a hash
// conflict in which case D shall be incremented for the latter of the conflicting certs.
//
// These links are used by openssl to lookup a given CA by subject name.
func GenerateHashLinks(dir string, certPaths []string) error {
	hashes := map[uint32][]string{}
	sort.Strings(certPaths)
	for _, path := range certPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file at path %q\n%w", path, err)
		}
		cert, err := decodeOneCert(raw)
		if err != nil {
			return fmt.Errorf("failed to decode certificate from file at path %q\n%w", path, err)
		}
		hash, err := SubjectNameHash(cert)
		if err != nil {
			return fmt.Errorf("failed compute subject name hash for cert at path %q\n%w", path, err)
		}
		hashes[hash] = append(hashes[hash], path)
	}
	for hash, paths := range hashes {
		for i, path := range paths {
			name := fmt.Sprintf("%08x.%d", hash, i)
			if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeOneCert(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed find PEM data")
	}
	extra, _ := pem.Decode(rest)
	if extra != nil {
		return nil, errors.New("found multiple PEM blocks, expected exactly one")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certficate\n%w", err)
	}
	return cert, nil
}

// SubjectNameHash is a reimplementation of the X509_subject_name_hash in openssl. It computes the SHA-1
// of the canonical encoding of the certificate's subject name and returns the 32-bit integer represented by the first
// four bytes of the hash using little-endian byte order.
func SubjectNameHash(cert *x509.Certificate) (uint32, error) {
	name, err := CanonicalName(cert.RawSubject)
	if err != nil {
		return 0, fmt.Errorf("failed to compute canonical subject name\n%w", err)
	}
	hasher := sha1.New()
	_, err = hasher.Write(name)
	if err != nil {
		return 0, fmt.Errorf("failed to compute sha1sum of canonical subject name\n%w", err)
	}
	sum := hasher.Sum(nil)
	return binary.LittleEndian.Uint32(sum[:4]), nil
}

// canonicalSET holds a of canonicalATVs. Suffix SET ensures it is marshaled as a set rather than a sequence
// by asn1.Marshal.
type canonicalSET []canonicalATV

// canonicalATV is similar to pkix.AttributeTypeAndValue but includes tag to ensure all values are marshaled as
// ASN.1, UTF8String values
type canonicalATV struct {
	Type  asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

// CanonicalName accepts a DER encoded subject name and returns a "Canonical Encoding" matching that
// returned by the x509_name_canon function in openssl. All string values are transformed with CanonicalString
// and UTF8 encoded and the leading SEQ header is removed.
//
// For more information see https://stackoverflow.com/questions/34095440/hash-algorithm-for-certificate-crl-directory.
func CanonicalName(name []byte) ([]byte, error) {
	var origSeq pkix.RDNSequence
	_, err := asn1.Unmarshal(name, &origSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject name\n%w", err)
	}
	var result []byte
	for _, origSet := range origSeq {
		var canonSet canonicalSET
		for _, origATV := range origSet {
			origVal, ok := origATV.Value.(string)
			if !ok {
				return nil, errors.New("got unexpected non-string value")
			}
			canonSet = append(canonSet, canonicalATV{
				Type:  origATV.Type,
				Value: CanonicalString(origVal),
			})
		}
		setBytes, err := asn1.Marshal(canonSet)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal canonical name\n%w", err)
		}
		result = append(result, setBytes...)
	}
	return result, nil
}

// CanonicalString transforms the given string. All leading and trailing whitespace is trimmed
// where whitespace is defined as a space, formfeed, tab, newline, carriage return, or vertical tab
// character. Any remaining sequence of one or more consecutive whitespace characters in replaced with
// a single ' '.
//
// This is a reimplementation of the asn1_string_canon in openssl
func CanonicalString(s string) string {
	s = strings.TrimLeft(s, " \f\t\n\v")
	s = strings.TrimRight(s, " \f\t\n\v")
	s = strings.ToLower(s)
	return string(regexp.MustCompile(`[[:space:]]+`).ReplaceAll([]byte(s), []byte(" ")))
}

func SplitCerts(path string, certDir string) ([]string, error) {
	var paths []string
	var block *pem.Block
	var rest []byte

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file at path %q\n%w", path, err)
	}

	block, rest = pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM data")
	} else if len(rest) == 0 {
		// only one cert found, use original path
		paths = append(paths, path)
		return paths, nil
	}
	for ind := 0; block != nil; ind++ {
		newCertPath := filepath.Join(certDir, fmt.Sprintf("cert_%d_%s", ind, filepath.Base(path)))
		if err = os.WriteFile(newCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), 0777); err != nil {
			return nil, fmt.Errorf("failed to write extra certficate to file\n%w", err)
		}
		paths = append(paths, newCertPath)
		block, rest = pem.Decode(rest)
		rest = bytes.TrimSpace(rest) // ignore any lines containing all spaces
		if block == nil && len(rest) > 0 {
			return nil, fmt.Errorf("failed to decode PEM data")
		}
	}
	return paths, nil
}
