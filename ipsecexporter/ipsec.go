package ipsecexporter

import (
	"strings"
	"regexp"
	"os/exec"
	"os"
	"bytes"
	"strconv"
	"io/ioutil"
	"github.com/prometheus/common/log"
	)

type IpSecConnection struct {
	name    string
}

type IpSecConfiguration struct {
	tunnel []IpSecConnection
}

type IpSecStatus struct {
	status map[string]int
}

const (
	down 		int = 0
	active 		int = 1
	unknown 	int = 2
)

func FetchIpSecConfiguration(fileName string) (IpSecConfiguration, error) {
	content, err := loadConfig(fileName)
	connectionNames := getConfiguredIpSecConnection(extractLines(content))

	return IpSecConfiguration{
		tunnel: connectionNames,
	}, err
}

func (c IpSecConfiguration) QueryStatus() IpSecStatus {
	s := IpSecStatus{
		status: map[string]int{},
	}

	for _, connection := range c.tunnel {


		cmd := exec.Command("ipsec", "status", connection.name)
		if out, err := cmd.Output(); err != nil {
			log.Warnf("Were not able to execute 'ipsec status %s'. %v", connection, err)
			s.status[connection.name] = unknown
		} else {
			status := getStatus(out)
			s.status[connection.name] = status
		}
	}

	return s
}

func (s IpSecStatus) PrometheusMetrics() string {
	var buffer bytes.Buffer

	buffer.WriteString("# HELP ipsec_status parsed ipsec status output\n")
	buffer.WriteString("# TYPE ipsec_status untyped\n")

	countContainers := execBash("docker ps -q | wc -l | tr -d '\n'")
	countActiveTunnels := execBash("ipsec status | grep -oP '(?<=active )[0-9]+' | tr -d '\n'")

    host, err := os.Hostname()
    if err != nil {
        panic(err)
    }

    for connection := range s.status {
        buffer.WriteString(`ipsec_status{tunnel="` + connection + `",containers="` + countContainers + `",active_tunnels="` + countActiveTunnels + `",hostname="` + host + `"} ` + strconv.Itoa(s.status[connection]) + "\n")
    }

	return buffer.String()
}

func execBash(command string) string{
	cmd := exec.Command("bash", "-c" , command)
	out, err := cmd.Output()
	if err != nil {
            log.Warnf("Failed to execute command: %s", cmd)
    }
    return string(out)
}

func getStatus(statusLine []byte) int {
	ipsecActiveRegex := regexp.MustCompile(`active [1-9]+`)
	ipsecDownRegex := regexp.MustCompile(`active [0]{1}`)
        countContainers := int(execBash("docker ps -q | wc -l | tr -d '\n'")[0])

	if ipsecActiveRegex.Match(statusLine) && countContainers > 2{
		return active

	} else if ipsecDownRegex.Match(statusLine) {
		return down

	}

	return unknown
}

func loadConfig(fileName string) (string, error) {
	buf, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	s := string(buf)
	return s, nil
}

func getConfiguredIpSecConnection(ipsecConfigLines []string) []IpSecConnection {
	connections := []IpSecConnection{}

	for _, line := range ipsecConfigLines {
		// Match connection definition lines
		re := regexp.MustCompile(`conn\s([a-zA-Z0-9_-]+)`)
		match := re.FindStringSubmatch(line)
		if len(match) >= 2 {
			connections = append(connections, IpSecConnection{name: match[1]})
		}

	}

	return connections
}

func extractLines(ipsecConfig string) []string {
	return strings.Split(ipsecConfig, "\n")
}