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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/buildpacks/libcnb"

	"github.com/paketo-buildpacks/libpak/bard"
)

type ExecD struct {
	Logger            bard.Logger
	Bindings          libcnb.Bindings
	GenerateHashLinks func(dir string, certPaths []string) error
	GetEnv            func(key string) string
}

func NewExecD(bindings libcnb.Bindings) *ExecD {
	return &ExecD{
		Bindings:          bindings,
		GenerateHashLinks: GenerateHashLinks,
		GetEnv:            os.Getenv,
	}
}

// Execute adds certificates from bindings of type "ca-certificates" to the system truststore at launch time.
func (e *ExecD) Execute() (map[string]string, error) {
	env := map[string]string{}
	paths := getsCertsFromBindings(e.Bindings)
	if len(paths) == 0 {
		return env, nil
	}
	certDir, err := ioutil.TempDir("", "ca-certs")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir\n%w", err)
	}
	if err := e.GenerateHashLinks(certDir, paths); err != nil {
		return nil, fmt.Errorf("failed to generate ca certficate symlinks\n%w", err)
	}
	e.Logger.Infof("Added %d additional CA certificate(s) to system truststore", len(paths))

	if v := e.GetEnv(EnvCAPath); v == "" {
		env[EnvCAPath] = certDir
	} else {
		env[EnvCAPath] = strings.Join([]string{v, certDir}, string(filepath.ListSeparator))
	}
	if v := e.GetEnv(EnvCAFile); v == "" {
		env[EnvCAFile] = DefaultCAFile
	}
	return env, nil
}
