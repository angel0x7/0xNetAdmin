package SystemInfo

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/disk"
)

type PartitionInfo struct {
	Device      string
	Mountpoint  string
	Fstype      string
	TotalGB     uint64
	UsedGB      uint64
	FreeGB      uint64
	UsedPercent float64
}

func GetPartitions() ([]PartitionInfo, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, fmt.Errorf("erreur partitions: %w", err)
	}

	var result []PartitionInfo
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		result = append(result, PartitionInfo{
			Device:      p.Device,
			Mountpoint:  p.Mountpoint,
			Fstype:      p.Fstype,
			TotalGB:     usage.Total / 1024 / 1024 / 1024,
			UsedGB:      usage.Used / 1024 / 1024 / 1024,
			FreeGB:      usage.Free / 1024 / 1024 / 1024,
			UsedPercent: usage.UsedPercent,
		})
	}
	return result, nil
}

type DiskIOStat struct {
	Name       string
	ReadMB     uint64
	WriteMB    uint64
	ReadCount  uint64
	WriteCount uint64
}

func GetDiskIO() ([]DiskIOStat, error) {
	counters, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}
	var result []DiskIOStat
	for name, io := range counters {
		result = append(result, DiskIOStat{
			Name:       name,
			ReadMB:     io.ReadBytes / 1024 / 1024,
			WriteMB:    io.WriteBytes / 1024 / 1024,
			ReadCount:  io.ReadCount,
			WriteCount: io.WriteCount,
		})
	}
	return result, nil
}
