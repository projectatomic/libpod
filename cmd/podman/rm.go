package main

import (
	"fmt"
	"os"

	"github.com/containers/libpod/cmd/podman/cliconfig"
	"github.com/containers/libpod/libpod"
	"github.com/containers/libpod/pkg/adapter"
	"github.com/containers/libpod/pkg/rootless"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	rmCommand     cliconfig.RmValues
	rmDescription = fmt.Sprintf(`Removes one or more containers from the host. The container name or ID can be used.

  Command does not remove images. Running containers will not be removed without the -f option.`)
	_rmCommand = &cobra.Command{
		Use:   "rm [flags] CONTAINER [CONTAINER...]",
		Short: "Remove one or more containers",
		Long:  rmDescription,
		RunE: func(cmd *cobra.Command, args []string) error {
			rmCommand.InputArgs = args
			rmCommand.GlobalFlags = MainGlobalOpts
			return rmCmd(&rmCommand)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			return checkAllAndLatest(cmd, args, false)
		},
		Example: `podman rm imageID
  podman rm mywebserver myflaskserver 860a4b23
  podman rm --force --all`,
	}
)

func init() {
	rmCommand.Command = _rmCommand
	rmCommand.SetHelpTemplate(HelpTemplate())
	rmCommand.SetUsageTemplate(UsageTemplate())
	flags := rmCommand.Flags()
	flags.BoolVarP(&rmCommand.All, "all", "a", false, "Remove all containers")
	flags.BoolVarP(&rmCommand.Force, "force", "f", false, "Force removal of a running container.  The default is false")
	flags.BoolVarP(&rmCommand.Latest, "latest", "l", false, "Act on the latest container podman is aware of")
	flags.BoolVarP(&rmCommand.Volumes, "volumes", "v", false, "Remove the volumes associated with the container")
	markFlagHiddenForRemoteClient("latest", flags)
}

// rmCmd removes one or more containers
func rmCmd(c *cliconfig.RmValues) error {
	if c.Bool("trace") {
		span, _ := opentracing.StartSpanFromContext(Ctx, "rmCmd")
		defer span.Finish()
	}

	if os.Geteuid() != 0 {
		rootless.SetSkipStorageSetup(true)
	}

	runtime, err := adapter.GetRuntime(&c.PodmanCommand)
	if err != nil {
		return errors.Wrapf(err, "could not get runtime")
	}
	defer runtime.Shutdown(false)

	ok, failures, err := runtime.RemoveContainers(getContext(), c)
	if err != nil {
		if errors.Cause(err) == libpod.ErrNoSuchCtr {
			exitCode = 1
			return nil
		}
		return err
	}
	return printCmdResults(ok, failures)
}
