package Network

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

// SelectInterface permet à l'utilisateur de choisir une interface réseau pour la capture de paquets.
func SelectInterface() string {
	// 1. Récupérer la liste des interfaces réseau disponibles
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Afficher les choix disponibles à l'utilisateur
	fmt.Println("Veuillez choisir une interface réseau :")
	for i, device := range devices {
		fmt.Printf("[%d] %s (%s)\n", i, device.Description, device.Name)
	}

	// 3. Lire le choix de l'utilisateur dans la console
	var choix int

	fmt.Print("\nEntrez le numéro de l'interface : ")
	_, err = fmt.Scanf("%d", &choix)
	if err != nil {
		log.Fatal("Entrée invalide.")
	}

	// Variable pour stocker l'interface sélectionnée
	var selectedDevice pcap.Interface

	// 4. Utilisation du switch case pour valider et enregistrer le choix
	switch {
	case choix >= 0 && choix < len(devices):
		selectedDevice = devices[choix]
		fmt.Printf("\nInterface enregistrée : %s\n", selectedDevice.Description)

	default:
		log.Fatalf("Choix invalide. Veuillez relancer et choisir un nombre entre 0 et %d.", len(devices)-1)
	}

	// 5. Vous pouvez maintenant utiliser selectedDevice.Name pour votre capture
	fmt.Printf("Prêt à ouvrir la capture sur : %s\n", selectedDevice.Name)

	return selectedDevice.Name
}
