package SystemInfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/mem"
)

type MemoryInfo struct {
	TotalMB     uint64
	UsedMB      uint64
	AvailableMB uint64
	UsedPercent float64
	SwapTotalMB uint64
	SwapUsedMB  uint64
}

func GetMemoryInfo() (*MemoryInfo, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("erreur RAM: %w", err)
	}
	swap, _ := mem.SwapMemory()

	return &MemoryInfo{
		TotalMB:     v.Total / 1024 / 1024,
		UsedMB:      v.Used / 1024 / 1024,
		AvailableMB: v.Available / 1024 / 1024,
		UsedPercent: v.UsedPercent,
		SwapTotalMB: swap.Total / 1024 / 1024,
		SwapUsedMB:  swap.Used / 1024 / 1024,
	}, nil
}
