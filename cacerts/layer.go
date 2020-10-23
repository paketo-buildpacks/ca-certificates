package cacerts

import (
	"os"
	"path/filepath"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Layer struct {
	CertPaths        []string
	LayerContributor libpak.LayerContributor
	LinkCerts        func(dir string, certPaths []string) error
	Logger           bard.Logger
}

func NewLayer(paths []string) *Layer {
	return &Layer{
		CertPaths:        paths,
		LayerContributor: libpak.NewLayerContributor("CA Certificates", map[string]interface{}{}),
		LinkCerts:        GenerateHashLinks,
	}
}

// Contribute create build layer adding the certificates at Layer.CAPaths to the set of trusted CAs.
func (v Layer) Contribute(layer libcnb.Layer) (libcnb.Layer, error) {
	v.LayerContributor.Logger = v.Logger

	return v.LayerContributor.Contribute(layer, func() (libcnb.Layer, error) {
		layer.BuildEnvironment = libcnb.Environment{}

		certsDir := filepath.Join(layer.Path, "certs")
		if err := os.Mkdir(certsDir, 0777); err != nil {
			return libcnb.Layer{}, err
		}
		if err := GenerateHashLinks(certsDir, v.CertPaths); err != nil {
			return libcnb.Layer{}, err
		}

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
