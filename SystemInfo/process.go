package SystemInfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessInfo struct {
	PID        int32
	Name       string
	CPUPercent float64
	MemoryMB   uint64
	Username   string
	Status     string
	CreateTime int64
	Exe        string
}

func GetRunningProcesses() ([]ProcessInfo, error) {
	pids, err := process.Pids()
	if err != nil {
		return nil, fmt.Errorf("erreur liste processus: %w", err)
	}

	var result []ProcessInfo
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		name, _ := p.Name()
		cpuPercent, _ := p.CPUPercent()
		memInfo, _ := p.MemoryInfo()
		username, _ := p.Username()
		status, _ := p.Status()
		createTime, _ := p.CreateTime()
		exe, _ := p.Exe()

		var memMB uint64
		if memInfo != nil {
			memMB = memInfo.RSS / 1024 / 1024
		}

		result = append(result, ProcessInfo{
			PID:        pid,
			Name:       name,
			CPUPercent: cpuPercent,
			MemoryMB:   memMB,
			Username:   username,
			Status:     fmt.Sprintf("%v", status),
			CreateTime: createTime,
			Exe:        exe,
		})
	}
	return result, nil
}

func KillProcess(pid int32) error {
	p, err := process.NewProcess(pid)
	if err != nil {
		return fmt.Errorf("processus PID %d introuvable: %w", pid, err)
	}

	if err := p.Terminate(); err != nil {
		if err := p.Kill(); err != nil {
			return fmt.Errorf("impossible d'arrêter le processus %d: %w", pid, err)
		}
	}
	return nil
}

func ProcessExists(pid int32) bool {
	exists, _ := process.PidExists(pid)
	return exists
}
