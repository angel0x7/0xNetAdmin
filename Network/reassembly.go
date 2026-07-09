package Network

import (
	"sort"
)

// ConnectionKey sert d'identifiant unique pour un flux TCP
type ConnectionKey struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// FluxTCP stocke désormais les fragments ainsi que le résultat final réassemblé
type FluxTCP struct {
	Fragments   map[uint32][]byte // Clé : SequenceNumber, Valeur : Data (payload)
	StreamFinal []byte            // Données réassemblées dans l'ordre correct
}

// AnalyserFluxTCP traite le dictionnaire et retourne les flux réassemblés
func AnalyserFluxTCP(dictionnaire map[string]TrameComplete) map[ConnectionKey]*FluxTCP {
	connexions := make(map[ConnectionKey]*FluxTCP)

	if len(dictionnaire) == 0 {
		return connexions
	}

	// Étape 1 : Regrouper les fragments de données par connexion TCP
	for _, trameComplete := range dictionnaire {
		if trameComplete.PaquetIPv4 == nil || trameComplete.PaquetTCP == nil || trameComplete.Application == nil {
			continue
		}

		if len(trameComplete.Application.Data) == 0 {
			continue
		}

		cle := ConnectionKey{
			SrcIP:   trameComplete.PaquetIPv4.SourceAddress,
			DstIP:   trameComplete.PaquetIPv4.DestinationAddress,
			SrcPort: trameComplete.PaquetTCP.SourcePort,
			DstPort: trameComplete.PaquetTCP.DestinationPort,
		}

		if _, existe := connexions[cle]; !existe {
			connexions[cle] = &FluxTCP{
				Fragments: make(map[uint32][]byte),
			}
		}

		// Dédoublonnement automatique grâce à la clé SequenceNumber
		seq := trameComplete.PaquetTCP.SequenceNumber
		connexions[cle].Fragments[seq] = trameComplete.Application.Data
	}

	// Étape 2 : Pour chaque connexion, trier les séquences et fusionner dans StreamFinal
	for _, flux := range connexions {
		// Récupération de toutes les clés de séquence
		var sequences []uint32
		for seq := range flux.Fragments {
			sequences = append(sequences, seq)
		}

		// Tri par ordre de SequenceNumber croissant
		sort.Slice(sequences, func(i, j int) bool {
			return sequences[i] < sequences[j]
		})

		// Allocation optimisée de la mémoire pour éviter les réallocations successives
		tailleTotale := 0
		for _, seq := range sequences {
			tailleTotale += len(flux.Fragments[seq])
		}
		flux.StreamFinal = make([]byte, 0, tailleTotale)

		// Fusion ordonnée des données
		for _, seq := range sequences {
			flux.StreamFinal = append(flux.StreamFinal, flux.Fragments[seq]...)
		}
	}

	return connexions
}
