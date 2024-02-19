// Package plasmactldeploy implements a deploy launchr plugin
package plasmactldeploy

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/apenella/go-ansible/pkg/execute"
	"github.com/apenella/go-ansible/pkg/options"
	"github.com/apenella/go-ansible/pkg/playbook"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/log"
	"github.com/spf13/cobra"
)

func init() {
	launchr.RegisterPlugin(&Plugin{})
}

// Plugin is launchr plugin providing bump action.
type Plugin struct{}

// PluginInfo implements launchr.Plugin interface.
func (p *Plugin) PluginInfo() launchr.PluginInfo {
	return launchr.PluginInfo{}
}

// OnAppInit implements launchr.Plugin interface.
func (p *Plugin) OnAppInit(_ launchr.App) error {
	return nil
}

// CobraAddCommands implements launchr.CobraPlugin interface to provide bump functionality.
func (p *Plugin) CobraAddCommands(rootCmd *cobra.Command) error {
	var pwbase64 string

	var dplCmd = &cobra.Command{
		Use:   "deploy [flags] environment tags",
		Short: "Deploy Ansible resources to target environment",
		Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Don't show usage help on a runtime error.
			cmd.SilenceUsage = true

			// @TODO investigate verbose not passed to sub-command
			// probably need to set it in launchr verbosity plugin ?
			//cmd.Flags().GetCount("verbose")

			return deploy(args[0], args[1], pwbase64)
		},
	}

	dplCmd.Flags().StringVar(&pwbase64, "pwbase64", "", "SSH Key passphrase")
	dplCmd.SetArgs([]string{"environment", "tags"})

	rootCmd.AddCommand(dplCmd)
	return nil
}

func deploy(environment, tags, password64 string) error {
	log.Info(fmt.Sprintf("ENVIRONMENT: %s", environment))
	log.Info(fmt.Sprintf("TAGS: %s", tags))

	vaultPassword, err := decodePassword(password64)
	if err != nil {
		return err
	}

	env := initEnv(environment, vaultPassword)
	ansiblePlaybookConnectionOptions := &options.AnsibleConnectionOptions{
		PrivateKey: tmpSSH,
	}

	ansiblePlaybookOptions := &playbook.AnsiblePlaybookOptions{
		Tags:              tags,
		VaultPasswordFile: tmpVault,
		VerboseVVV:        true,
	}

	// set extra vars
	xv := env.getExtraVars()
	for k, v := range xv {
		err = ansiblePlaybookOptions.AddExtraVar(k, v)
		if err != nil {
			return err
		}
	}

	// set environment vars
	executor := execute.NewDefaultExecute(
		execute.WithEnvVar("ANSIBLE_VAULT_PASSWORD_FILE", tmpVault),
	)
	ev := env.getEnvVars()
	for k, v := range ev {
		executor.EnvVars[k] = v
	}

	cmd := &playbook.AnsiblePlaybookCmd{
		Playbooks:         []string{"platform/platform.yaml"},
		ConnectionOptions: ansiblePlaybookConnectionOptions,
		Options:           ansiblePlaybookOptions,
		Exec:              executor,
	}

	log.Info("\n  Ansible playbook command:\n%s\n\n", cmd.String())
	err = cmd.Run(context.TODO())
	if err != nil {
		panic(err)
	}

	return err
}

func decodePassword(base64String string) (string, error) {
	if base64String == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
