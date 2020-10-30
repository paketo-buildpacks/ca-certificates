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
