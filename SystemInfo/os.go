package SystemInfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/host"
)

type OSInfo struct {
	Hostname   string
	Platform   string
	Version    string
	KernelArch string
	Uptime     uint64
	BootTime   uint64
}

func GetOSInfo() (*OSInfo, error) {
	info, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("erreur récupération info OS: %w", err)
	}
	return &OSInfo{
		Hostname:   info.Hostname,
		Platform:   info.Platform,
		Version:    info.PlatformVersion,
		KernelArch: info.KernelArch,
		Uptime:     info.Uptime,
		BootTime:   info.BootTime,
	}, nil
}
