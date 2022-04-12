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

package cacerts

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"

	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/sherpa"
)

const (
	CACertsDir    = "ca-certificates"
	EmbedCertsDir = "embedded-certs"
)

type TrustedCACerts struct {
	CertPaths         []string
	EmbeddedCerts     bool
	GenerateHashLinks func(dir string, certPaths []string) error
	LayerContributor  libpak.LayerContributor
	Logger            bard.Logger
}

func NewTrustedCACerts(paths []string, embedCACerts bool) *TrustedCACerts {
	return &TrustedCACerts{
		CertPaths:         paths,
		GenerateHashLinks: GenerateHashLinks,
		EmbeddedCerts:     embedCACerts,
		LayerContributor: libpak.NewLayerContributor(
			"CA Certificates",
			map[string]interface{}{},
			libcnb.LayerTypes{
				Build:  true,
				Launch: embedCACerts,
			},
		),
	}
}

// Contribute create build layer adding the certificates at Layer.CAPaths to the set of trusted CAs.
func (l TrustedCACerts) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	l.LayerContributor.Logger = l.Logger

	return l.LayerContributor.Contribute(layer, func() (libcnb.Layer, error) {
		certsDir := filepath.Join(layer.Path, CACertsDir)

		if err := os.Mkdir(certsDir, 0755); err != nil {
			return libcnb.Layer{}, fmt.Errorf("failed to create directory %q\n%w", certsDir, err)
		}

		if l.EmbeddedCerts {
			if err := l.ContributeEmbedCACerts(layer); err != nil {
				return libcnb.Layer{}, err
			}

			layer.LaunchEnvironment.Append(EnvCAPath, string(filepath.ListSeparator), certsDir)
			layer.LaunchEnvironment.Default(EnvCAFile, DefaultCAFile)
		}

		if err := l.GenerateHashLinks(certsDir, l.CertPaths); err != nil {
			return libcnb.Layer{}, fmt.Errorf("failed to generate CA certificate symlinks\n%w", err)
		}

		l.Logger.Bodyf("Added %d additional CA certificate(s) to system truststore", len(l.CertPaths))

		layer.BuildEnvironment.Append(
			EnvCAPath,
			string(filepath.ListSeparator),
			certsDir,
		)
		layer.BuildEnvironment.Default(EnvCAFile, DefaultCAFile)

		return layer, nil
	})
}

func (l *TrustedCACerts) ContributeEmbedCACerts(layer libcnb.Layer) error {
	l.Logger.Body("Embedding CA certificate(s)")

	embeddedDir := filepath.Join(layer.Path, EmbedCertsDir)
	if err := os.Mkdir(embeddedDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q\n%w", embeddedDir, err)
	}

	newCertPaths := []string{}
	for _, certPath := range l.CertPaths {
		certFile, err := os.Open(certPath)
		if err != nil {
			return fmt.Errorf("failed to open cert %q\n%w", certPath, err)
		}

		dest := filepath.Join(embeddedDir, filepath.Base(certPath))
		err = sherpa.CopyFile(certFile, dest)
		if err != nil {
			return fmt.Errorf("failed to copy cert %q to %q\n%w", certPath, dest, err)
		}
		newCertPaths = append(newCertPaths, dest)
	}
	l.CertPaths = newCertPaths

	return nil
}

func (TrustedCACerts) Name() string {
	return "ca-certificates"
}
