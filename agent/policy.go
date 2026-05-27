package main

import (
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type policyFile struct {
	Egress struct {
		Allow []string `yaml:"allow"`
	} `yaml:"egress"`
}

// AllowList holds pre-resolved IPs from the egress allowlist.
type AllowList struct {
	IPs map[string]bool
}

// LoadPolicy reads a payloadguard-policy.yaml file and resolves all allowed
// hostnames to IPs at startup. Returns a permissive empty allowlist if the
// file does not exist or cannot be parsed.
func LoadPolicy(path string) (*AllowList, error) {
	al := &AllowList{IPs: make(map[string]bool)}
	if path == "" {
		return al, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return al, nil // no policy file = permissive
	}
	var p policyFile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return al, err
	}
	for _, host := range p.Egress.Allow {
		addrs, _ := net.LookupHost(host)
		for _, a := range addrs {
			al.IPs[a] = true
		}
	}
	return al, nil
}

func (al *AllowList) IsAllowed(ip string) bool {
	if len(al.IPs) == 0 {
		return true // permissive when no policy loaded
	}
	return al.IPs[ip]
}
