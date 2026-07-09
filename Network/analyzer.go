package Network

import (
	"crypto/md5"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// AnalyserTexte convertit proprement les octets applicatifs en texte imprimable
func AnalyserTexte(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			builder.WriteByte(b)
		} else {
			builder.WriteByte('.') // Remplacement des octets non-imprimables
		}
	}
	return builder.String()
}

// CalculerEntropie mesure le niveau d'aléa des données (proche de 8 = hautement chiffré ou compressé)
func CalculerEntropie(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	occurrences := make(map[byte]int)
	for _, b := range data {
		occurrences[b]++
	}
	var entropie float64
	taille := float64(len(data))
	for _, count := range occurrences {
		p := float64(count) / taille
		entropie -= p * math.Log2(p)
	}
	return entropie
}

// InspecterContenu analyse le flux et détermine s'il est chiffré ou non, et quel est son protocole
func InspecterContenu(flux *FluxReseau) (bool, string, string) {
	data := flux.StreamFinal
	if len(data) == 0 {
		return false, "Inconnu", "Aucune donnée"
	}

	texte := AnalyserTexte(data)

	// =========================================================================
	// 1. DÉTECTION DES PROTOCOLES CHIFFRÉS (CRYPTE)
	// =========================================================================

	// TLS / HTTPS (Client Hello : commence généralement par 0x16 0x03 0x01 ou 0x03 0x03)
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 && (data[2] == 0x01 || data[2] == 0x03) {
		return true, "TLS / HTTPS", "Poignée de main (Handshake) TLS détectée"
	}

	// SSH (Bannière texte visible au tout début du flux binaire)
	if strings.HasPrefix(texte, "SSH-1.") || strings.HasPrefix(texte, "SSH-2.") {
		return true, "SSH", fmt.Sprintf("Session SSH sécurisée (%s)", strings.Split(texte, "\r\n")[0])
	}

	// WireGuard (VPN - Type de message 1, 2, 3 ou 4 au début du payload UDP, suivi de 3 octets réservés à 0)
	if flux.Protocol == "UDP" && len(data) >= 4 && (data[0] >= 1 && data[0] <= 4) && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return true, "WireGuard (VPN)", "Trafic de tunnel chiffré WireGuard"
	}

	// Heuristique par Entropie pour le trafic chiffré inconnu
	// Si le flux est volumineux et que l'entropie est très élevée (> 7.5), c'est probablement du chiffrement pur
	entropie := CalculerEntropie(data)
	if len(data) > 100 && entropie > 7.5 {
		return true, "Chiffré (Inconnu)", fmt.Sprintf("Forte suspicion de chiffrement (Entropie: %.2f/8.0)", entropie)
	}

	// =========================================================================
	// 2. DÉTECTION DES PROTOCOLES NON-CHIFFRÉS (EN CLAIR)
	// =========================================================================

	// HTTP
	if regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+ HTTP/\d\.\d`).MatchString(texte) || strings.HasPrefix(texte, "HTTP/1.") {
		return false, "HTTP", "Trafic Web en clair"
	}

	// FTP
	if regexp.MustCompile(`^(220|331|230|200|530) `).MatchString(texte) || regexp.MustCompile(`^(USER|PASS|PORT|PASV|LIST|QUIT)\s`).MatchString(texte) {
		return false, "FTP", "Commandes de transfert de fichiers"
	}

	// SMTP
	if regexp.MustCompile(`^(220|250|354) \S+ E?SMTP`).MatchString(texte) || regexp.MustCompile(`^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA)\s`).MatchString(texte) {
		return false, "SMTP", "Échange de mails non-sécurisé"
	}

	// DNS
	if flux.Protocol == "UDP" && len(data) >= 12 && ((data[2] == 0x01 && data[3] == 0x00) || (data[2] == 0x81 && data[3] == 0x80)) {
		return false, "DNS", "Requête/Réponse de résolution de nom"
	}
	if flux.Protocol == "TCP" && len(data) >= 14 && ((data[4] == 0x01 && data[5] == 0x00) || (data[4] == 0x81 && data[5] == 0x80)) {
		return false, "DNS (TCP)", "Zone Transfer ou requête DNS longue"
	}

	// ICMP Spécifique (Ping Windows / Linux)
	if flux.Protocol == "ICMP" {
		if strings.Contains(texte, "abcdefghijklmnopqrstuvw") {
			return false, "ICMP (Ping)", "Ping standard Microsoft Windows"
		}
		return false, "ICMP", "Message de contrôle réseau"
	}

	// Si rien n'a matché mais que l'entropie est basse, c'est du texte ou du binaire simple inconnu
	return false, "Texte/Binaire brut", fmt.Sprintf("Protocole inconnu en clair (Entropie: %.2f)", entropie)
}
func AfficherAnalyseFlux(connexions map[ConnectionKey]*FluxReseau) {
	if len(connexions) == 0 {
		fmt.Println("[!] Aucun flux à analyser.")
		return
	}

	fmt.Println("\n========================================================================")
	fmt.Println("         RAPPORT D'ANALYSE APPLICATIVE GLOBALE (CRYPTE VS CLAIR)        ")
	fmt.Println("========================================================================")

	for cle, flux := range connexions {
		if len(flux.StreamFinal) == 0 {
			continue
		}

		estCrypte, proto, details := InspecterContenu(flux)
		texteExtrait := AnalyserTexte(flux.StreamFinal)

		if estCrypte {
			fmt.Printf("🔒 [CHIFFRÉ] Protocole: %s | %s\n", proto, details)
		} else {
			fmt.Printf("🔓 [EN CLAIR] Protocole: %s | %s\n", proto, details)
		}

		// 1. AFFICHAGE COUCHE 2 - PHYSIQUE (Ethernet MAC)
		fmt.Printf("     Physique: MAC %02x:%02x:%02x:%02x:%02x:%02x ➔ %02x:%02x:%02x:%02x:%02x:%02x\n",
			flux.SourceMAC[0], flux.SourceMAC[1], flux.SourceMAC[2], flux.SourceMAC[3], flux.SourceMAC[4], flux.SourceMAC[5],
			flux.DestinationMAC[0], flux.DestinationMAC[1], flux.DestinationMAC[2], flux.DestinationMAC[3], flux.DestinationMAC[4], flux.DestinationMAC[5])

		// 2. AFFICHAGE COUCHE 3 - RÉSEAU (Liaison IP & Détails IPv4)
		if cle.Protocol == "ICMP" {
			icmpType := cle.SrcPort >> 8
			icmpCode := cle.SrcPort & 0x00FF
			fmt.Printf("     Réseau  : %d.%d.%d.%d ➔ %d.%d.%d.%d [ICMP Type %d, Code %d]\n",
				cle.SrcIP[0], cle.SrcIP[1], cle.SrcIP[2], cle.SrcIP[3],
				cle.DstIP[0], cle.DstIP[1], cle.DstIP[2], cle.DstIP[3], icmpType, icmpCode)
		} else {
			fmt.Printf("     Réseau  : %s | %d.%d.%d.%d:%d ➔ %d.%d.%d.%d:%d\n",
				cle.Protocol,
				cle.SrcIP[0], cle.SrcIP[1], cle.SrcIP[2], cle.SrcIP[3], cle.SrcPort,
				cle.DstIP[0], cle.DstIP[1], cle.DstIP[2], cle.DstIP[3], cle.DstPort)
		}

		// Extraction de la Version et du Header Length (IHL) depuis VersionAndIHL
		version := flux.VersionAndIHL >> 4
		ihl := (flux.VersionAndIHL & 0x0F) * 4 // L'IHL est exprimé en mots de 32 bits, on multiplie par 4 pour l'avoir en octets

		fmt.Printf("     IPv4 Hdr: Version=%d | IHL=%d octets | TOS=0x%02x | TTL=%d\n",
			version, ihl, flux.TypeOfService, flux.TTL)
		fmt.Printf("               TotalLength=%d | ID=%d | Flags/Offset=0x%04x | Checksum=0x%04x\n",
			flux.TotalLength, flux.Identification, flux.FlagsAndFragmentOffset, flux.HeaderChecksum)

		// 3. AFFICHAGE COUCHE 7 - APPLICATION
		fmt.Printf("     Volume  : %d octets applicatifs réassemblés\n", len(flux.StreamFinal))
		fmt.Println("----- EXTRAIT DU CONTENU -----")

		if estCrypte {
			// Calcul de l'empreinte MD5 pour le contenu chiffré
			hash := md5.Sum(flux.StreamFinal)
			fmt.Printf("[Données Chiffrées] Empreinte MD5 du payload: %x\n", hash)
		} else {
			apercu := texteExtrait
			if len(apercu) > 200 {
				apercu = apercu[:200] + "\n[... Suite des données en clair masquée ...]"
			}
			fmt.Println(apercu)
		}
		fmt.Println("========================================================================\n")
	}
}
