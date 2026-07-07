package main

import (
	"Go_Reseau/SystemInfo"
	"fmt"
	"time"
)

func main() {

	osInfo, err := SystemInfo.GetOSInfo()
	if err != nil {
		fmt.Printf("Erreur : %v\n", err)
		return
	}
	fmt.Printf("Informations sur le système d'exploitation :\n")
	fmt.Printf("  Nom d'hôte : %s\n", osInfo.Hostname)
	fmt.Printf("  Plateforme : %s\n", osInfo.Platform)
	fmt.Printf("  Version : %s\n", osInfo.Version)
	fmt.Printf("  Architecture du noyau : %s\n", osInfo.KernelArch)
	fmt.Printf("  Temps de fonctionnement : %d secondes\n", osInfo.Uptime)
	fmt.Printf("  Heure de démarrage : %s\n", time.Unix(int64(osInfo.BootTime), 0).Format("2006-01-02 15:04:05"))

	connections, err := SystemInfo.GetOpenConnections()
	SystemInfo.PrintConnections(connections)
	if err != nil {
		fmt.Printf("Erreur lors de la récupération des connexions : %v\n", err)
		return
	}
	//testing installed_apps

	installedApps, err := SystemInfo.GetInstalledApplications()
	if err != nil {
		fmt.Printf("Erreur lors de la récupération des applications installées : %v\n", err)
		return
	}
	fmt.Printf("\nApplications installées :\n")
	for _, app := range installedApps {
		fmt.Printf("  Nom : %s, Version : %s\n, SizeMB: %d ", app.Name, app.Version, app.SizeMB)
	}

}
