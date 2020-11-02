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
	"github.com/buildpacks/libcnb"
)

type Detect struct{}

const (
	// PlanEntryCACerts if present in the build plan indicates that certificates should be added to the
	// truststore at build time.
	PlanEntryCACerts = "ca-certificates"
	// PlanEntryCACertsHelper if present in the build plan indicates the the ca-cert-helper binary should be
	// contributed to the app image.
	PlanEntryCACertsHelper = "ca-certificates-helper"
)

// Detect always passes and optionally provides ca-certificates. If there is a binding of
// type "ca-certificates" Detect also requires ca-certificates and provides an array of certificate paths in the
// plan entry metadata.
func (Detect) Detect(context libcnb.DetectContext) (libcnb.DetectResult, error) {
	result := libcnb.DetectResult{
		Pass: true,
		Plans: []libcnb.BuildPlan{
			{
				Provides: []libcnb.BuildPlanProvide{
					{Name: PlanEntryCACertsHelper},
					{Name: PlanEntryCACerts},
				},
				Requires: []libcnb.BuildPlanRequire{
					{Name: PlanEntryCACertsHelper},
				},
			},
			{
				Provides: []libcnb.BuildPlanProvide{
					{Name: PlanEntryCACertsHelper},
				},
				Requires: []libcnb.BuildPlanRequire{
					{Name: PlanEntryCACertsHelper},
				},
			},
		},
	}
	paths := getsCertsFromBindings(context.Platform.Bindings)
	if len(paths) > 0 {
		result.Plans[0].Requires = append(result.Plans[0].Requires, libcnb.BuildPlanRequire{
			Name: PlanEntryCACerts,
			Metadata: map[string]interface{}{
				"paths": paths,
			},
		})
	}
	return result, nil
}
