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
	"strconv"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak"
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

// Detect always passes by default and optionally provides ca-certificates. If there is a binding of
// type "ca-certificates" Detect also requires ca-certificates and provides an array of certificate paths in the
// plan entry metadata.
//
// To prevent default detection, users can set the
// BP_RUNTIME_CERT_BINDING_DISABLED environment variable to "true" at
// build-time. This will disable the helper layer, and the buildpack will only
// detect if there is no ca-certificates binding present at build-time.
func (d Detect) Detect(context libcnb.DetectContext) (libcnb.DetectResult, error) {
	provides := []libcnb.BuildPlanProvide{
		{Name: PlanEntryCACerts},
	}

	requires := []libcnb.BuildPlanRequire{}

	// If there are CA cert bindings at build time, require PlanEntryCACerts
	paths := getsCertsFromBindings(context.Platform.Bindings)
	if len(paths) > 0 {
		requires = append(requires, libcnb.BuildPlanRequire{
			Name: PlanEntryCACerts,
			Metadata: map[string]interface{}{
				"paths": paths,
			},
		})
	}

	result := libcnb.DetectResult{
		Pass: true,
		Plans: []libcnb.BuildPlan{
			{
				Provides: provides,
				Requires: requires,
			},
		},
	}

	// If BP_RUNTIME_CERT_BINDING_DISABLED = true, do not enable helper layer.
	cr, err := libpak.NewConfigurationResolver(context.Buildpack, nil)
	if err != nil {
		return libcnb.DetectResult{}, fmt.Errorf("unable to create configuration resolver\n%w", err)
	}

	if ok, err := d.runtimeCertBindingEnabled(cr); !ok {
		if err != nil {
			return libcnb.DetectResult{}, err
		}
		return result, nil
	}

	// Add helper layer build plan entries
	helperProvide := libcnb.BuildPlanProvide{Name: PlanEntryCACertsHelper}
	helperRequire := libcnb.BuildPlanRequire{Name: PlanEntryCACertsHelper}
	result.Plans[0].Provides = append(result.Plans[0].Provides, helperProvide)
	result.Plans[0].Requires = append(result.Plans[0].Requires, helperRequire)

	result.Plans = append(result.Plans, libcnb.BuildPlan{
		Provides: []libcnb.BuildPlanProvide{helperProvide},
		Requires: []libcnb.BuildPlanRequire{helperRequire},
	})

	return result, nil
}

func (d Detect) runtimeCertBindingEnabled(cr libpak.ConfigurationResolver) (bool, error) {
	if cr.ResolveBool("BP_RUNTIME_CERT_BINDING_DISABLED") {
		return false, nil
	}

	// Deprecated: Remove support for this environment variable in the future
	if val, isSet := cr.Resolve("BP_ENABLE_RUNTIME_CERT_BINDING"); isSet {
		enable, err := strconv.ParseBool(val)
		if err != nil {
			return false, fmt.Errorf(
				"invalid value '%s' for key '%s': expected one of [1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False]",
				val,
				"BP_ENABLE_RUNTIME_CERT_BINDING",
			)
		}
		return enable, nil
	}

	return true, nil
}
