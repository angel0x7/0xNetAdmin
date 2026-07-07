package SystemInfo

import (
	"golang.org/x/sys/windows/registry"
)

type InstalledApp struct {
	Name        string
	Version     string
	Publisher   string
	InstallDate string
	SizeMB      uint64
	InstallLoc  string
}

func GetInstalledApplications() ([]InstalledApp, error) {
	var apps []InstalledApp

	uninstallPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	for _, path := range uninstallPaths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}

		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, name := range names {
			subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			displayName, _, err := subKey.GetStringValue("DisplayName")
			if err != nil || displayName == "" {
				subKey.Close()
				continue
			}

			version, _, _ := subKey.GetStringValue("DisplayVersion")
			publisher, _, _ := subKey.GetStringValue("Publisher")
			installDate, _, _ := subKey.GetStringValue("InstallDate")
			installLoc, _, _ := subKey.GetStringValue("InstallLocation")

			sizeKB, _, err := subKey.GetIntegerValue("EstimatedSize")
			var sizeMB uint64
			if err == nil {
				sizeMB = sizeKB / 1024
			}

			apps = append(apps, InstalledApp{
				Name:        displayName,
				Version:     version,
				Publisher:   publisher,
				InstallDate: installDate,
				SizeMB:      sizeMB,
				InstallLoc:  installLoc,
			})
			subKey.Close()
		}
	}
	return apps, nil
}
