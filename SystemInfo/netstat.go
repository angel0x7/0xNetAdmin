package SystemInfo

import (
	"fmt"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type Connection struct {
	Proto       string
	LocalAddr   string
	LocalPort   uint32
	RemoteAddr  string
	RemotePort  uint32
	State       string
	PID         int32
	ProcessName string
}

func GetOpenConnections() ([]Connection, error) {
	conns, err := psnet.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("erreur récupération connexions: %w", err)
	}

	var result []Connection
	for _, c := range conns {

		if c.Status == "NONE" {
			continue
		}

		procName := "inconnu"
		if c.Pid > 0 {
			if p, err := process.NewProcess(c.Pid); err == nil {
				if name, err := p.Name(); err == nil {
					procName = name
				}
			}
		}

		result = append(result, Connection{
			Proto:       protoFromType(c.Type),
			LocalAddr:   c.Laddr.IP,
			LocalPort:   c.Laddr.Port,
			RemoteAddr:  c.Raddr.IP,
			RemotePort:  c.Raddr.Port,
			State:       c.Status,
			PID:         c.Pid,
			ProcessName: procName,
		})
	}
	return result, nil
}

func protoFromType(t uint32) string {
	switch t {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return "?"
	}
}

func GetListeningPorts() ([]Connection, error) {
	all, err := GetOpenConnections()
	if err != nil {
		return nil, err
	}
	var listening []Connection
	for _, c := range all {
		if c.State == "LISTEN" {
			listening = append(listening, c)
		}
	}
	return listening, nil

}

func PrintConnections(conns []Connection) {
	fmt.Printf("%-6s %-22s %-22s %-12s %-8s %s\n", "PROTO", "LOCAL", "DISTANT", "ÉTAT", "PID", "PROCESSUS")
	for _, c := range conns {
		local := fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort)
		remote := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)
		fmt.Printf("%-6s %-22s %-22s %-12s %-8d %s\n",
			c.Proto, local, remote, c.State, c.PID, c.ProcessName)
	}
}
