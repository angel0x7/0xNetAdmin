package Network

import (
	"fmt"
	"sort"
	"strings"
)

// IPStats stocke les métriques accumulées pour une adresse IP spécifique
type IPStats struct {
	IP             [4]byte
	BytesSent      uint64
	BytesReceived  uint64
	TotalBytes     uint64
	Protocols      map[string]uint64 // Volume par protocole pour cette IP
	MainProtocol   string
	Geoloc         string
	StatusSecurity string
}

// GlobalStats centralise les métriques de l'ensemble de la capture
type GlobalStats struct {
	TotalBytes       uint64
	ProtocolVolumes  map[string]uint64
	ProtocolSecurity map[string]string // "Chiffré" ou "En clair"
	IPMetrics        map[[4]byte]*IPStats
}

// NewGlobalStats initialise la structure de statistiques
func NewGlobalStats() *GlobalStats {
	return &GlobalStats{
		ProtocolVolumes:  make(map[string]uint64),
		ProtocolSecurity: make(map[string]string),
		IPMetrics:        make(map[[4]byte]*IPStats),
	}
}

// ObtenirGeolocSimule simule une base GeoIP (à remplacer par MaxMind GeoLite2 en production)
func ObtenirGeolocSimule(ip [4]byte) string {
	// Détection des IP privées (RFC 1918)
	if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
		return "Réseau Local (LAN)"
	}
	if ip[0] == 127 {
		return "Loopback"
	}

	// Simulation pour les IP publiques
	switch ip[0] % 3 {
	case 0:
		return "États-Unis (AWS)"
	case 1:
		return "Europe (OVH)"
	default:
		return "Asie (Alibaba)"
	}
}

func CalculerStatistiquesGlobales(connexions map[ConnectionKey]*FluxReseau) *GlobalStats {
	stats := NewGlobalStats()

	for cle, flux := range connexions {
		volumeFlux := uint64(len(flux.StreamFinal))
		if volumeFlux == 0 {
			continue
		}

		// 1. Analyse du contenu du flux (Chiffré vs Clair)
		estCrypte, proto, _ := InspecterContenu(flux)

		// 2. Accumulation globale par protocole
		stats.TotalBytes += volumeFlux
		stats.ProtocolVolumes[proto] += volumeFlux
		if estCrypte {
			stats.ProtocolSecurity[proto] = "🟢 Chiffré"
		} else if proto != "ICMP" && proto != "Texte/Binaire brut" {
			stats.ProtocolSecurity[proto] = "🚨 En clair"
		} else {
			stats.ProtocolSecurity[proto] = "🔓 Neutre"
		}

		// 3. Métriques pour l'IP Source
		if _, existe := stats.IPMetrics[cle.SrcIP]; !existe {
			stats.IPMetrics[cle.SrcIP] = &IPStats{IP: cle.SrcIP, Protocols: make(map[string]uint64), Geoloc: ObtenirGeolocSimule(cle.SrcIP)}
		}
		stats.IPMetrics[cle.SrcIP].BytesSent += volumeFlux
		stats.IPMetrics[cle.SrcIP].TotalBytes += volumeFlux
		stats.IPMetrics[cle.SrcIP].Protocols[proto] += volumeFlux

		// 4. Métriques pour l'IP Destination
		if _, existe := stats.IPMetrics[cle.DstIP]; !existe {
			stats.IPMetrics[cle.DstIP] = &IPStats{IP: cle.DstIP, Protocols: make(map[string]uint64), Geoloc: ObtenirGeolocSimule(cle.DstIP)}
		}
		stats.IPMetrics[cle.DstIP].BytesReceived += volumeFlux
		stats.IPMetrics[cle.DstIP].TotalBytes += volumeFlux
		stats.IPMetrics[cle.DstIP].Protocols[proto] += volumeFlux

		// Ajuster le statut de sécurité de l'IP si elle utilise du texte en clair
		if !estCrypte && proto != "ICMP" && proto != "Texte/Binaire brut" {
			stats.IPMetrics[cle.SrcIP].StatusSecurity = "🚨 À risque"
			stats.IPMetrics[cle.DstIP].StatusSecurity = "🚨 À risque"
		}
	}

	// 5. Post-traitement : Trouver le protocole majoritaire pour chaque IP
	for _, ipStat := range stats.IPMetrics {
		var maxVol uint64
		var protoMaj = "Aucun"
		for proto, vol := range ipStat.Protocols {
			if vol > maxVol {
				maxVol = vol
				protoMaj = proto
			}
		}
		ipStat.MainProtocol = protoMaj
		if ipStat.StatusSecurity == "" {
			ipStat.StatusSecurity = "🟢 Sécurisé"
		}
	}

	return stats
}

func AfficherTableauxBord(stats *GlobalStats) {
	fmt.Println("\n==========================================================================================")
	fmt.Println("                      TABLEAU DE BORD ADM RECON / SÉCURITÉ RÉSEAU                        ")
	fmt.Println("==========================================================================================")
	fmt.Printf("Volume total analysé : %d octets\n\n", stats.TotalBytes)

	// -------------------------------------------------------------------------
	// TABLEAU 1 : TOP DES ADRESSES IP (Classé par volume décroissant)
	// -------------------------------------------------------------------------
	fmt.Println("### TOP DES CONSOMMATEURS RESEAU (ADRESSES IP)")
	fmt.Printf("| %-15s | %-10s | %-10s | %-12s | %-15s | %-20s | %-10s |\n",
		"Adresse IP", "Envoyé", "Reçu", "Total Vol.", "Proto Maj.", "Géolocalisation", "Sécurité")
	fmt.Println("|-----------------|------------|------------|--------------|-----------------|----------------------|----------|")

	// Tri des IP par volume total
	var listeIPs []*IPStats
	for _, v := range stats.IPMetrics {
		listeIPs = append(listeIPs, v)
	}
	sort.Slice(listeIPs, func(i, j int) bool {
		return listeIPs[i].TotalBytes > listeIPs[j].TotalBytes
	})

	for _, ipStat := range listeIPs {
		strIP := fmt.Sprintf("%d.%d.%d.%d", ipStat.IP[0], ipStat.IP[1], ipStat.IP[2], ipStat.IP[3])
		fmt.Printf("| %-15s | %-10d | %-10d | %-12d | %-15s | %-20s | %-10s |\n",
			strIP, ipStat.BytesSent, ipStat.BytesReceived, ipStat.TotalBytes,
			ipStat.MainProtocol, ipStat.Geoloc, ipStat.StatusSecurity)
	}

	fmt.Println("\n" + strings.Repeat("-", 90) + "\n")

	// -------------------------------------------------------------------------
	// TABLEAU 2 : RÉPARTITION ET VOLUMÉTRIE DES PROTOCOLES
	// -------------------------------------------------------------------------
	fmt.Println("### RÉPARTITION DES PROTOCOLES APPLICATIFS DÉTECTÉS")
	fmt.Printf("| %-20s | %-15s | %-15s | %-15s |\n", "Protocole", "Volume Global", "Part Trafic (%)", "Statut Sécurité")
	fmt.Println("|----------------------|-----------------|-----------------|-----------------|")

	for proto, vol := range stats.ProtocolVolumes {
		pourcentage := 0.0
		if stats.TotalBytes > 0 {
			pourcentage = (float64(vol) / float64(stats.TotalBytes)) * 100
		}
		fmt.Printf("| %-20s | %-15d | %-13.2f%% | %-15s |\n",
			proto, vol, pourcentage, stats.ProtocolSecurity[proto])
	}
	fmt.Println("==========================================================================================\n")
}
