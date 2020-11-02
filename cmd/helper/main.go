package main

import (
	"fmt"
	"os"

	"github.com/buildpacks/libcnb"
	"github.com/paketo-buildpacks/libpak/bard"
	"github.com/paketo-buildpacks/libpak/sherpa"

	"github.com/paketo-buildpacks/ca-certificates/cacerts"
)

func main() {
	sherpa.Execute(func() error {
		bindings, err := libcnb.NewBindingsFromEnvironment()
		if err != nil {
			return fmt.Errorf("unable to read bindings from environment\n%w", err)
		}

		cacertHelper := cacerts.NewExecD(bindings)
		cacertHelper.Logger = bard.NewLogger(os.Stdout)
		return sherpa.Helpers(map[string]sherpa.ExecD{
			"ca-cert-helper": cacertHelper,
		})
	})
}
