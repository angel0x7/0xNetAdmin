package main

import (
	"Go_Reseau/internal"
	"fmt"
)

func main() {
	interfaceName := internal.SelectInterface()
	fmt.Printf("Interface sélectionnée : %s\n", interfaceName)
	fmt.Println("Démarrage de la capture de paquets...")
	fmt.Println("Nombre de paquet a capturer")
	compteur := 0
	fmt.Scanf("%d", &compteur)
	TrameCompleteMap := internal.ScanLayers(interfaceName, compteur)
	fmt.Printf("Total de paquets capturés : %d\n", len(TrameCompleteMap))
	fmt.Printf("Détails des paquets capturés :\n")
	for cle, trameComplete := range TrameCompleteMap {
		fmt.Printf("Paquet %s :\n", cle)
		fmt.Printf("  Trame : %+v\n", *trameComplete.Trame)
		fmt.Printf("Timestamp :%s\n", trameComplete.TimeStamp.Format("15:04:05.000"))
		if trameComplete.PaquetIPv4 != nil {
			fmt.Printf("  Paquet IPv4 : %+v\n", *trameComplete.PaquetIPv4)
		}
		if trameComplete.PaquetTCP != nil {
			fmt.Printf("  Paquet TCP : %+v\n", *trameComplete.PaquetTCP)
		}
		if trameComplete.PaquetUDP != nil {
			fmt.Printf("  Paquet UDP : %+v\n", *trameComplete.PaquetUDP)
		}
	}

}
