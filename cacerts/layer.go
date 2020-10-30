package cacerts

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Layer struct {
	CertPaths         []string
	LayerContributor  libpak.LayerContributor
	GenerateHashLinks func(dir string, certPaths []string) error
	Logger            bard.Logger
}

func NewLayer(paths []string) *Layer {
	return &Layer{
		CertPaths:         paths,
		LayerContributor:  libpak.NewLayerContributor("CA Certificates", map[string]interface{}{}),
		GenerateHashLinks: GenerateHashLinks,
	}
}

// Contribute create build layer adding the certificates at Layer.CAPaths to the set of trusted CAs.
func (l Layer) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	l.LayerContributor.Logger = l.Logger

	return l.LayerContributor.Contribute(layer, func() (libcnb.Layer, error) {
		layer.BuildEnvironment = libcnb.Environment{}

		certsDir := filepath.Join(layer.Path, "certs")
		if err := os.Mkdir(certsDir, 0777); err != nil {
			return libcnb.Layer{}, fmt.Errorf("failed to create directory %q\n%w", certsDir, err)
		}
		if err := l.GenerateHashLinks(certsDir, l.CertPaths); err != nil {
			return libcnb.Layer{}, fmt.Errorf("failed to generate certificate symlinks\n%w", err)
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

func (Layer) Name() string {
	return "ca-certificates"
}
