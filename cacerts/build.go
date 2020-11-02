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
	"errors"
	"fmt"
	"sort"
	"strings"

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

	var certPaths []string
	var contributedHelper bool
	for _, e := range context.Plan.Entries {
		switch strings.ToLower(e.Name) {
		case PlanEntryCACerts:
			paths, err := pathsFromEntryMetadata(e.Metadata)
			if err != nil {
				return libcnb.BuildResult{}, fmt.Errorf("failed to decode CA certificate paths from plan entry:\n%w", err)
			}
			certPaths = append(certPaths, paths...)
		case PlanEntryCACertsHelper:
			if contributedHelper {
				continue
			}
			h := libpak.NewHelperLayerContributor(
				context.Buildpack,
				&context.Plan,
				ExecutableCACertsHelper,
			)
			h.Logger = b.Logger
			result.Layers = append(result.Layers, h)
			contributedHelper = true
		default:
			return libcnb.BuildResult{}, fmt.Errorf("received unexpected buildpack plan entry %q", e.Name)
		}
	}

	if len(certPaths) > 0 {
		sort.Strings(certPaths)
		layer := NewTrustedCACerts(certPaths)
		layer.Logger = b.Logger
		result.Layers = append(result.Layers, layer)
	}

	return result, nil
}

func pathsFromEntryMetadata(md map[string]interface{}) ([]string, error) {
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
