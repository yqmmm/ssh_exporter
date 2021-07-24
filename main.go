package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

var configPath string

type Config struct {
	Script      string             `yaml:"script"`
	Credentials []CredentialConfig `yaml:"credentials"`
}

type CredentialConfig struct {
	Host    string `yaml:"host"`
	User    string `yaml:"user"`
	KeyFile string `yaml:"keyfile"`
}

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func parseConfig(c string) Config {
	raw, err := ioutil.ReadFile(c)
	Check(err)

	config := Config{}
	err = yaml.Unmarshal([]byte(raw), &config)
	Check(err)

	return config
}

func connect(host, user, keyfile string) (*ssh.Client, *ssh.Session, error) {
	key := getKeyFile(keyfile)

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sshConfig.SetDefaults()

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), sshConfig)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}

	return client, session, nil
}

func getKeyFile(keyfile string) ssh.Signer {
	log.Printf("Usingkeyfile: %s", keyfile)
	buf, err := ioutil.ReadFile(keyfile)
	Check(err)

	key, err := ssh.ParsePrivateKey(buf)
	Check(err)

	return key
}

func main() {
	flag.StringVar(&configPath, "config", "config.yml", "Path to configuration")
	config := parseConfig(configPath)
	log.Printf("Using config: %s", configPath)

	script, err := ioutil.ReadFile(config.Script)
	Check(err)

	for _, cred := range config.Credentials {
		log.Printf("Connecting to %s", cred.Host)

		client, session, err := connect(cred.Host, cred.User, cred.KeyFile)
		Check(err)

		out, err := session.CombinedOutput(string(script))
		Check(err)
		fmt.Println(string(out))

		session.Close()
		client.Close()
	}
}
