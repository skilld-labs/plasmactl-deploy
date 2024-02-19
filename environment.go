package plasmactldeploy

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bigkevmcd/go-configparser"
	"github.com/launchrctl/launchr/pkg/log"
	vault "github.com/sosedoff/ansible-vault-go"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	toolboxCfg = "toolbox/config.yaml"
	tmpVault   = "/tmp/vault"
	tmpCluster = "/tmp/cluster"
	tmpSSH     = "/tmp/id_rsa"
	vaultFile  = "platform/group_vars/platform/vault.yaml"
)

type cluster struct {
	environment   string
	vaultPassword string
	config        toolboxConfig
}

type toolboxConfig struct {
	Environment struct {
		Dev     toolboxEnvConfig `yaml:"dev"`
		Prod    toolboxEnvConfig `yaml:"prod"`
		Sandbox toolboxEnvConfig `yaml:"sandbox"`
	} `yaml:"environment"`
	Bus struct {
		Event struct {
			Application string `yaml:"application"`
			Port        string `yaml:"port"`
		} `yaml:"event"`
		Data struct {
			Application string `yaml:"application"`
			Port        string `yaml:"port"`
			Namespace   string `yaml:"namespace"`
			Svc         string `yaml:"svc"`
			PodName     string `yaml:"pod_name"`
			Service     string `yaml:"service"`
		} `yaml:"data"`
	} `yaml:"bus"`
}

type toolboxEnvConfig struct {
	Name                 string    `yaml:"name"`
	IP                   string    `yaml:"ip"`
	ExtraVars            extraVars `yaml:"extra_vars"`
	EnvironmentVariables struct {
		MachineDomainName string `yaml:"machine_domain_name"`
		MachineDomainExt  string `yaml:"machine_domain_ext"`
	} `yaml:"environment_variables"`
	Bus struct {
		Data struct {
			BrokerCount int `yaml:"broker_count"`
		} `yaml:"data"`
	} `yaml:"bus"`
}

type extraVars struct {
	MachineEnv string `yaml:"machine_env"`
}

func initEnv(environment, password string) *cluster {
	config := getConfig(toolboxCfg)
	vaultPass := password

	if vaultPass == "" {
		fmt.Print("- Enter Ansible vault password: ")
		passwordBytes, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			panic("...")
		}
		vaultPass = string(passwordBytes)
	}

	clustr := &cluster{environment: environment, vaultPassword: vaultPass, config: config}
	clustr.prepareCluster()
	clustr.prepareVaultPass()
	clustr.prepareSSHKey()

	return clustr
}

func (clustr *cluster) getEnvVars() map[string]string {
	ansibleConfig, err := configparser.NewConfigParserFromFile("ansible.cfg")
	if err != nil {
		panic("Cant find ansible cfg")
	}

	envVars := make(map[string]string)
	envVars["ANSIBLE_VAULT_PASSWORD_FILE"] = tmpVault
	envVars["ANSIBLE_CALLBACK_PLUGINS"], err = ansibleConfig.Get("defaults", "callback_plugins")
	if err != nil {
		panic(`Cant find ansible cfg`)
	}
	envVars["ANSIBLE_STDOUT_CALLBACK"], err = ansibleConfig.Get("defaults", "stdout_callback")
	if err != nil {
		panic(`Cant find ansible cfg`)
	}

	clusterConfig := clustr.GetClusterConfig()
	envVars["MACHINE_DOMAIN_NAME"] = clusterConfig.EnvironmentVariables.MachineDomainName
	envVars["MACHINE_DOMAIN_EXT"] = clusterConfig.EnvironmentVariables.MachineDomainExt

	for k, v := range envVars {
		log.Info(fmt.Sprintf("ENV_VAR: %s - %s", k, v))
	}

	return envVars
}

func (clustr *cluster) getExtraVars() map[string]string {
	config := clustr.GetClusterConfig()

	ev := make(map[string]string)
	ev["machine_env"] = config.ExtraVars.MachineEnv

	for k, v := range ev {
		log.Info(fmt.Sprintf("EXTRA_VAR: %s - %s", k, v))
	}

	return ev
}

func (clustr *cluster) GetClusterConfig() toolboxEnvConfig {
	var config = toolboxEnvConfig{}
	switch clustr.environment {
	case "dev":
		config = clustr.config.Environment.Dev
	case "prod":
		config = clustr.config.Environment.Prod
	case "sandbox":
		config = clustr.config.Environment.Sandbox
	default:
		panic(fmt.Sprintf("Environment %s not found in config", clustr.environment))
	}

	return config
}

func (clustr *cluster) prepareCluster() {
	fmt.Printf("Preparing cluster file %s\n", tmpCluster)

	config := clustr.GetClusterConfig()
	clusterName := config.Name
	err := os.WriteFile(tmpCluster, []byte(clusterName), 0600)
	if err != nil {
		panic(fmt.Sprintf("Coudln't write cluster into %s", tmpCluster))
	}
}

func (clustr *cluster) prepareSSHKey() {
	vy, err := vault.DecryptFile(vaultFile, clustr.vaultPassword)
	if err != nil {
		panic(err)
	}

	var vaultMap map[string]interface{}
	err = yaml.Unmarshal([]byte(vy), &vaultMap)
	if err != nil {
		panic("Can't unmarshall vault")
	}

	if value, ok := vaultMap["vault_user_ssh_private_key"].(string); ok {
		err = os.WriteFile(tmpSSH, []byte(value), 0600)
		if err != nil {
			panic(err)
		}
	} else {
		panic("Not possible to write ssh key")
	}
}

func (clustr *cluster) prepareVaultPass() {
	fmt.Printf("Preparing vault pass file %s\n", tmpVault)
	err := os.WriteFile(tmpVault, []byte(clustr.vaultPassword), 0600)
	if err != nil {
		panic(err)
	}
}

func getConfig(path string) toolboxConfig {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		log.Debug("%s", err)
		panic("Can't load config for environment")
	}

	var config toolboxConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Debug("%s", err)
		panic("Can't load config for environment")
	}

	return config
}
