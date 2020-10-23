package cacerts

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak/bard"
)

type Detect struct {
	Logger bard.Logger
}

const (
	BindingType = "ca-certificates"
)

// Detect always passes and optionally provides ca-certificates. If there is a binding of
// type "ca-certficates" Detect also requires ca-certificates and provides an array of cerficate paths in the
// plan entry metadata.
func (Detect) Detect(context libcnb.DetectContext) (libcnb.DetectResult, error) {
	paths := getsCertsFromBindings(context.Platform.Bindings)
	if len(paths) > 0 {
		sort.Strings(paths)
		return libcnb.DetectResult{Pass: true, Plans: []libcnb.BuildPlan{{
			Provides: []libcnb.BuildPlanProvide{
				{Name: "ca-certificates"},
			},
			Requires: []libcnb.BuildPlanRequire{
				{
					Name: "ca-certificates",
					Metadata: map[string]interface{}{
						"paths": paths,
					},
				},
			},
		}}}, nil
	}

	return libcnb.DetectResult{
		Pass: true,
		Plans: []libcnb.BuildPlan{
			{
				Provides: []libcnb.BuildPlanProvide{
					{Name: "ca-certificates"},
				},
			},
			{},// always contribute runtime helper
		},
	}, nil
}

func getsCertsFromBindings(bindings libcnb.Bindings) []string {
	var paths []string
	for _, bind := range bindings {
		if strings.ToLower(bind.Type) == strings.ToLower(BindingType) {
			for k := range bind.Secret {
				paths = append(paths, filepath.Join(bind.Path, k))
			}
		}
	}
	sort.Strings(paths)
	return paths
}
