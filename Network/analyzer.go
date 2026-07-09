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

		// Formatage de l'en-tête selon le chiffrement
		statusChiffrement := "🟢 [CHIFFRÉ]"
		if !estCrypte && proto != "ICMP" && proto != "Texte/Binaire brut" {
			statusChiffrement := "🚨 [ALERTE EN CLAIR - VULNÉRABLE]"
			_ = statusChiffrement // Évite le warning go
		}

		if estCrypte {
			fmt.Printf("🔒 %s Protocole: %s | %s\n", statusChiffrement, proto, details)
		} else {
			fmt.Printf("🔓 [EN CLAIR] Protocole: %s | %s\n", proto, details)
		}

		// Affichage de la liaison réseau
		if cle.Protocol == "ICMP" {
			icmpType := cle.SrcPort >> 8
			icmpCode := cle.SrcPort & 0x00FF
			fmt.Printf("     Liaison : %d.%d.%d.%d ➔ %d.%d.%d.%d [ICMP Type %d, Code %d]\n",
				cle.SrcIP[0], cle.SrcIP[1], cle.SrcIP[2], cle.SrcIP[3],
				cle.DstIP[0], cle.DstIP[1], cle.DstIP[2], cle.DstIP[3], icmpType, icmpCode)
		} else {
			fmt.Printf("     Liaison : %s | %d.%d.%d.%d:%d ➔ %d.%d.%d.%d:%d\n",
				cle.Protocol,
				cle.SrcIP[0], cle.SrcIP[1], cle.SrcIP[2], cle.SrcIP[3], cle.SrcPort,
				cle.DstIP[0], cle.DstIP[1], cle.DstIP[2], cle.DstIP[3], cle.DstPort)
		}

		fmt.Printf("     Taille  : %d octets réassemblés\n", len(flux.StreamFinal))

		// Contenu visuel : Si c'est en clair, on montre le texte. Si c'est chiffré, on montre une empreinte.
		fmt.Println("----- EXTRAIT DU CONTENU -----")
		if estCrypte {
			// Pour le chiffré, afficher le texte brut n'a pas de sens (ce ne sont que des points),
			// on génère une empreinte MD5 pour prouver l'intégrité ou l'identité de la payload
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
