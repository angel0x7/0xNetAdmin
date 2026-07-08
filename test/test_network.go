package test

import (
	"Go_Reseau/Network"
	"Go_Reseau/ScanApplicationLayer"
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

	ScanApplicationLayer.AppProtocolsUncrypted(dictionnaire)
}
