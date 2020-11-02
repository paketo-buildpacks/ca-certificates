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

package cacerts

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"

	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type TrustedCACerts struct {
	CertPaths         []string
	LayerContributor  libpak.LayerContributor
	GenerateHashLinks func(dir string, certPaths []string) error
	Logger            bard.Logger
}

func NewTrustedCACerts(paths []string) *TrustedCACerts {
	return &TrustedCACerts{
		CertPaths:         paths,
		LayerContributor:  libpak.NewLayerContributor("CA Certificates", map[string]interface{}{}),
		GenerateHashLinks: GenerateHashLinks,
	}
}

// Contribute create build layer adding the certificates at Layer.CAPaths to the set of trusted CAs.
func (l TrustedCACerts) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	l.LayerContributor.Logger = l.Logger

	return l.LayerContributor.Contribute(layer, func() (libcnb.Layer, error) {
		layer.BuildEnvironment = libcnb.Environment{}

		certsDir := filepath.Join(layer.Path, "ca-certificates")
		if err := os.Mkdir(certsDir, 0777); err != nil {
			return libcnb.Layer{}, fmt.Errorf("failed to create directory %q\n%w", certsDir, err)
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
	}, libpak.BuildLayer)
}

func (TrustedCACerts) Name() string {
	return "ca-certificates"
}
