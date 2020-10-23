package cacerts

import (
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
// the trusts the ca certificates at the paths provided in the plan entry metadata.
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
		result.Layers = append(result.Layers, NewLayer(certPaths))
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
		return nil, fmt.Errorf("ca-certificates build plan entry is missing required metadata key \"dirs\"")
	}
	pathArr, ok := rawPaths.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected \"paths\" to be of type []interface{}")
	}
	certPaths := make([]string, len(pathArr))
	for i, path := range pathArr {
		var ok bool
		certPaths[i], ok = path.(string)
		if !ok {
			return nil, fmt.Errorf("expected each item in \"paths\" to be of type string")
		}
	}
	return certPaths, nil
}
