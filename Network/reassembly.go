package Network

import (
	"sort"
)

// ConnectionKey identifie un flux unique de manière générique
type ConnectionKey struct {
	Protocol string // "TCP", "UDP" ou "ICMP"
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16 // Pour ICMP, stockera le Type (byte supérieur) et Code (byte inférieur)
	DstPort  uint16 // Pour ICMP Echo, peut stocker l'ID du message pour lier les flux
}

// FluxReseau stocke les données accumulées
type FluxReseau struct {
	Protocol    string
	Fragments   map[uint64][]byte // Trié par Seq (TCP) ou par Temps (UDP/ICMP)
	StreamFinal []byte
}

// AnalyserFluxMultiProtocoles traite le dictionnaire et gère TCP, UDP et ICMP
func AnalyserFluxMultiProtocoles(dictionnaire map[string]TrameComplete) map[ConnectionKey]*FluxReseau {
	connexions := make(map[ConnectionKey]*FluxReseau)

	if len(dictionnaire) == 0 {
		return connexions
	}

	for _, trameComplete := range dictionnaire {
		if trameComplete.PaquetIPv4 == nil {
			continue
		}

		var proto string
		var srcPort, dstPort uint16
		var cleCle uint64
		var payload []byte

		// On extrait les données selon le protocole détecté
		if trameComplete.PaquetTCP != nil {
			proto = "TCP"
			srcPort = trameComplete.PaquetTCP.SourcePort
			dstPort = trameComplete.PaquetTCP.DestinationPort
			cleCle = uint64(trameComplete.PaquetTCP.SequenceNumber)
			if trameComplete.Application != nil {
				payload = trameComplete.Application.Data
			}

		} else if trameComplete.PaquetUDP != nil {
			proto = "UDP"
			srcPort = trameComplete.PaquetUDP.SourcePort
			dstPort = trameComplete.PaquetUDP.DestinationPort
			cleCle = uint64(trameComplete.TimeStamp.UnixNano())
			if trameComplete.Application != nil {
				payload = trameComplete.Application.Data
			}

		} else if trameComplete.PaquetICMP != nil {
			proto = "ICMP"

			// On pack le Type et le Code dans srcPort (Ex: Type 8, Code 0 -> 0x0800)
			srcPort = (uint16(trameComplete.PaquetICMP.Type) << 8) | uint16(trameComplete.PaquetICMP.Code)

			// Votre structure n'a pas d'Identifier, on initialise dstPort à 0
			dstPort = 0

			// Tri chronologique basé sur le temps de capture
			cleCle = uint64(trameComplete.TimeStamp.UnixNano())

			// Récupération du payload : l'en-tête (Type, Code, Checksum) fait 4 octets.
			// On extrait tout ce qui se trouve après ces 4 octets.
			// Remplacez 'DataBrute' par le nom du champ qui contient les octets de cette couche dans votre TrameComplete
			if len(trameComplete.Application.Data) > 4 {
				payload = trameComplete.Application.Data[4:]
			}
		} else {
			continue
		}

		// S'il n'y a pas de données du tout (ex: paquet TCP ACK vide), on passe au suivant
		if len(payload) == 0 {
			continue
		}

		cle := ConnectionKey{
			Protocol: proto,
			SrcIP:    trameComplete.PaquetIPv4.SourceAddress,
			DstIP:    trameComplete.PaquetIPv4.DestinationAddress,
			SrcPort:  srcPort,
			DstPort:  dstPort,
		}

		if _, existe := connexions[cle]; !existe {
			connexions[cle] = &FluxReseau{
				Protocol:  proto,
				Fragments: make(map[uint64][]byte),
			}
		}

		connexions[cle].Fragments[cleCle] = payload
	}

	// Étape 2 : Reconstruction finale
	for _, flux := range connexions {
		var indexTries []uint64
		for idx := range flux.Fragments {
			indexTries = append(indexTries, idx)
		}

		sort.Slice(indexTries, func(i, j int) bool {
			return indexTries[i] < indexTries[j]
		})

		tailleTotale := 0
		for _, idx := range indexTries {
			tailleTotale += len(flux.Fragments[idx])
		}
		flux.StreamFinal = make([]byte, 0, tailleTotale)

		for _, idx := range indexTries {
			flux.StreamFinal = append(flux.StreamFinal, flux.Fragments[idx]...)
		}
	}

	return connexions
}
