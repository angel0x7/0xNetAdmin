package test

import (
	"Go_Reseau/Network"
	"fmt"
)

func TestScanLayers() {
	fmt.Println("Scanning network layers...")
	NetworkInterface := Network.SelectInterface()
	fmt.Printf("Selected interface: %s\n", NetworkInterface)
	fmt.Println("Starting packet capture...")
	var compteur int = 0

	for compteur <= 0 {
		fmt.Printf("Enter the number of packets to capture (0 for unlimited): ")
		fmt.Scanf("%d", &compteur)
	}

	dictionnaire := Network.ScanLayers(NetworkInterface, compteur)
	FluxTCP := Network.AnalyserFluxMultiProtocoles(dictionnaire)
	// Affichage de la data du flux TCP réassemblé
	for cle, flux := range FluxTCP {
		fmt.Printf("Flux détecté depuis %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
			cle.SrcIP[0], cle.SrcIP[1], cle.SrcIP[2], cle.SrcIP[3], cle.SrcPort,
			cle.DstIP[0], cle.DstIP[1], cle.DstIP[2], cle.DstIP[3], cle.DstPort)

		// Vous avez accès au buffer final nettoyé et ordonné ici :
		fmt.Printf("Contenu réassemblé (%d octets) :\n%s\n",
			len(flux.StreamFinal), string(flux.StreamFinal))
	}
	/*	for key, trame := range dictionnaire {
		fmt.Printf("\nPacket %s:\n", key)
		fmt.Printf("Timestamp: %s\n", trame.TimeStamp.Format(time.RFC3339))
		if trame.PaquetIPv4 != nil {
			fmt.Printf("IPv4 Packet: %+v\n", *trame.PaquetIPv4)
		}
		if trame.PaquetTCP != nil {
			fmt.Printf("TCP Packet: %+v\n", *trame.PaquetTCP)
		}
		if trame.PaquetUDP != nil {
			fmt.Printf("UDP Packet: %+v\n", *trame.PaquetUDP)
		}
		if trame.PaquetICMP != nil {
			fmt.Printf("ICMP Packet: %+v\n", *trame.PaquetICMP)
		}
		if trame.Application != nil {
			fmt.Printf("Application Data: %+v\n", *trame.Application)
		}

	}*/

	//ScanApplicationLayer.AppProtocolsUncrypted(dictionnaire)
}
