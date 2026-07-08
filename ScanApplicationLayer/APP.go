package ScanApplicationLayer

import (
	"Go_Reseau/Network"
	"fmt"
	"strings"
)

func AppProtocolsUncrypted(dictionnaire map[string]Network.TrameComplete) {
	applicationProtocolsNonChiffre := []string{"HTTP", "FTP", "SMTP", "SNMP", "Telnet", "LLMNR", "DNS", "DHCP", "TFTP", "NTP", "IMAP", "POP3", "LDAP", "RDP", "SIP", "RTSP", "IRC", "XMPP"}

	for key, datapaquet := range dictionnaire {
		if datapaquet.Application == nil || len(datapaquet.Application.Data) == 0 {
			continue
		}
		//appdata := datapaquet.Application.Data
		apptext := datapaquet.Application.Texte
		for _, protocol := range applicationProtocolsNonChiffre {
			if strings.Contains(apptext, protocol) {
				fmt.Printf("Packet %s contains %s protocol data.\n", key, protocol)
				fmt.Printf("Application Data: %s\n", apptext)
				break
			}
		}

	}
}
func IsTLSHandshake(data []byte) bool {
	// Vérifie si la longueur des données est suffisante pour contenir un en-tête TLS
	if len(data) < 5 {
		return false
	}
	IsTLSHandshake := data[0] == 0x16 && data[1] == 0x03 && (data[2] == 0x00 || data[2] == 0x01 || data[2] == 0x02 || data[2] == 0x03)
	return IsTLSHandshake
}

/*
func AppProtocolsCrypted(dictionnaire map[string]Network.TrameComplete) {
	applicationProtocolsChiffre := []string{"HTTPS", "SSH", "SMTPS", "IMAPS", "POP3S", "FTPS", "SFTP"}
	appdata := datapaquet.Application.Data
	for key, datapaquet := range dictionnaire {
		if datapaquet.Application == nil || len(datapaquet.Application.Data) == 0 {
			continue
		}

	}
}
*/
