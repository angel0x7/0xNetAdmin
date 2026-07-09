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
	// --- Informations de Couche 2 (Ethernet) ---
	DestinationMAC [6]byte
	SourceMAC      [6]byte

	// --- Informations de Couche 3 (IPv4) ---
	VersionAndIHL          byte
	TypeOfService          byte
	TotalLength            uint16
	Identification         uint16
	FlagsAndFragmentOffset uint16
	TTL                    byte
	HeaderChecksum         uint16
}

// AnalyserFluxMultiProtocoles traite le dictionnaire et gère TCP, UDP et ICMP
// AnalyserFluxMultiProtocoles traite le dictionnaire et gère TCP, UDP, ICMP en incluant MAC et IPv4
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

		// 1. Détermination du protocole et extraction de la payload spécifique
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
			srcPort = (uint16(trameComplete.PaquetICMP.Type) << 8) | uint16(trameComplete.PaquetICMP.Code)
			dstPort = 0
			cleCle = uint64(trameComplete.TimeStamp.UnixNano())

			// Extraction depuis DataBrute si l'en-tête ICMP minimal fait 4 octets
			if len(trameComplete.Application.Data) > 4 {
				payload = trameComplete.Application.Data[4:]
			}
		} else {
			continue
		}

		// Optionnel : si vous souhaitez analyser uniquement les paquets contenant de la donnée
		if len(payload) == 0 {
			continue
		}

		// Création de la clé unique du flux
		cle := ConnectionKey{
			Protocol: proto,
			SrcIP:    trameComplete.PaquetIPv4.SourceAddress,
			DstIP:    trameComplete.PaquetIPv4.DestinationAddress,
			SrcPort:  srcPort,
			DstPort:  dstPort,
		}

		// 2. Initialisation et enrichissement des métadonnées lors de la création du flux
		if _, existe := connexions[cle]; !existe {
			flux := &FluxReseau{
				Protocol:  proto,
				Fragments: make(map[uint64][]byte),
			}

			// Capture des informations Ethernet (si votre structure Couche 2 est présente)
			// Adapter 'PaquetEthernet' selon le nom exact dans votre structure TrameComplete
			if trameComplete.Trame != nil {
				flux.DestinationMAC = trameComplete.Trame.DestinationMAC
				flux.SourceMAC = trameComplete.Trame.SourceMAC
			}

			// Capture des informations détaillées IPv4
			flux.VersionAndIHL = trameComplete.PaquetIPv4.VersionAndIHL
			flux.TypeOfService = trameComplete.PaquetIPv4.TypeOfService
			flux.TotalLength = trameComplete.PaquetIPv4.TotalLength
			flux.Identification = trameComplete.PaquetIPv4.Identification
			flux.FlagsAndFragmentOffset = trameComplete.PaquetIPv4.FlagsAndFragmentOffset
			flux.TTL = trameComplete.PaquetIPv4.TTL
			flux.HeaderChecksum = trameComplete.PaquetIPv4.HeaderChecksum

			connexions[cle] = flux
		}

		// Ajout du fragment courant
		connexions[cle].Fragments[cleCle] = payload
	}

	// 3. Étape de reconstruction (Tri et fusion)
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
