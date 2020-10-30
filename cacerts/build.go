package cacerts

import (
	"errors"
	"fmt"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Build struct {
	Logger bard.Logger
}

// Build returns a libcnb.BuildResult for the given context. Build always contributes a launch layer containing the
// ca-cert-helper executable.
//
// If the buildpack plan contains an entry with name "ca-certificates" Build will contribute a build layer
// that adds the ca certificates at the paths provided in the plan entry metadata to the system truststore.
func (b Build) Build(context libcnb.BuildContext) (libcnb.BuildResult, error) {
	var result libcnb.BuildResult

	b.Logger.Title(context.Buildpack)

	for _, e := range context.Plan.Entries {
		if e.Name != "ca-certificates" {
			return libcnb.BuildResult{}, fmt.Errorf("received unexpected build plan entry %q", e.Name)
		}
		certPaths, err := pathFromEntryMetadata(e.Metadata)
		if err != nil {
			return libcnb.BuildResult{}, fmt.Errorf("failed to decode CA certificate paths from plan entry:\n%w", err)
		}
		layer := NewLayer(certPaths)
		layer.Logger = b.Logger
		result.Layers = append(result.Layers, layer)
	}

	h := libpak.NewHelperLayerContributor(
		context.Buildpack,
		&context.Plan,
		"ca-cert-helper",
	)
	h.Logger = b.Logger
	result.Layers = append(result.Layers, h)

	return result, nil
}

func pathFromEntryMetadata(md map[string]interface{}) ([]string, error) {
	rawPaths, ok := md["paths"]
	if !ok {
		return nil, errors.New("ca-certificates build plan entry is missing required metadata key \"dirs\"")
	}
	pathArr, ok := rawPaths.([]interface{})
	if !ok {
		return nil, errors.New("expected \"paths\" to be of type []interface{}")
	}
	certPaths := make([]string, len(pathArr))
	for i, path := range pathArr {
		var ok bool
		certPaths[i], ok = path.(string)
		if !ok {
			return nil, errors.New("expected each item in \"paths\" to be of type string")
		}
	}
	return certPaths, nil
}
