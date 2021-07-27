package connect

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

var conf Config

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func SoftCheck(e error) bool {
	if e != nil {
		log.Printf("Soft error: %v", e)
		return true
	} else {
		return false
	}
}

type Config struct {
	Script      string              `yaml:"script"`
	Credentials []*CredentialConfig `yaml:"credentials"`
}

type CredentialConfig struct {
	Host    string `yaml:"host"`
	User    string `yaml:"user"`
	KeyFile string `yaml:"keyfile"`
}

type Result struct {
	Config *CredentialConfig
	Output string
	Loads  map[string]string
}

func ParseConfig(c string) Config {
	raw, err := ioutil.ReadFile(c)
	Check(err)

	config := Config{}
	err = yaml.Unmarshal([]byte(raw), &config)
	Check(err)

	return config
}

func ParseArgs() string {
	var configPath string
	var port string

	flag.StringVar(&configPath, "config", "config.yml", "Path to configuration")
	conf = ParseConfig(configPath)
	log.Printf("Using config: %s", configPath)

	flag.StringVar(&port, "port", "9428", "Port probed metrics are served on.")
	log.Printf("Using port: %s", port)

	return port
}

func getKeyFile(keyfile string) ssh.Signer {
	buf, err := ioutil.ReadFile(keyfile)
	Check(err)

	key, err := ssh.ParsePrivateKey(buf)
	Check(err)

	return key
}

func Connect(host, user, keyfile string) (*ssh.Client, *ssh.Session, error) {
	key := getKeyFile(keyfile)

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
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

func parseResult(r *Result) {
	output := r.Output
	r.Loads = make(map[string]string)

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, l := range lines {
		parts := strings.Fields(l)
		if len(parts) < 2 {
			log.Printf("Invalid result line: %s", l)
			continue
		}
		user := parts[0]
		load := parts[1]
		r.Loads[user] = load
	}
}

func formatResult(r *Result) string {
	parseResult(r)

	response := ""
	for user, load := range r.Loads {
		if user == "system" {
			response = fmt.Sprintf("%sprobe_cpu_usage_total{host=\"%s\"} %s\n", response, r.Config.Host, load)
		} else {
			response = fmt.Sprintf("%sprobe_cpu_usage_per_user{host=\"%s\", user=\"%s\"} %s\n", response, r.Config.Host, user, load)
		}
	}
	return response
}

func formatResults(r []*Result) string {
	response := ""
	sort.Slice(r, func(i, j int) bool {
		return r[i].Config.Host < r[j].Config.Host
	})
	for _, r := range r {
		response = fmt.Sprintf("%s%s", response, formatResult(r))
	}
	return response
}

func execute(cred []*CredentialConfig) []*Result {
	// TODO: Cache this
	script, err := ioutil.ReadFile(conf.Script)
	Check(err)

	rc := make(chan *Result)
	for _, c := range cred {
		go func(c *CredentialConfig) {
			log.Printf("Connecting to %s", c.Host)

			client, session, err := Connect(c.Host, c.User, c.KeyFile)
			if SoftCheck(err) {
				rc <- nil
				return
			}

			out, err := session.CombinedOutput(string(script))
			if SoftCheck(err) {
				rc <- nil
				return
			}

			rc <- &Result{
				Config: c,
				Output: string(out),
				Loads:  nil,
			}

			session.Close()
			client.Close()
		}(c)
	}

	var results []*Result
	for i := 0; i < len(cred); i++ {
		res := <-rc
		if res != nil {
			results = append(results, res)
		}
	}

	return results
}

func ProbeHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	var to_execute []*CredentialConfig
	if host == "" {
		to_execute = conf.Credentials
	} else {
		for _, c := range conf.Credentials {
			if c.Host == host {
				log.Printf("Found host: %s", host)
				to_execute = append(to_execute, c)
				break
			}
		}
	}

	if len(to_execute) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "No host found: %v", host)
		return
	}

	results := execute(to_execute)

	fmt.Fprintf(w, "%s", formatResults(results))
}
