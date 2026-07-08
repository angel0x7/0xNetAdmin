package Network

import (
	"encoding/binary"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Trame struct {
	DestinationMAC [6]byte
	SourceMAC      [6]byte
	EtherType      uint16
}
type PaquetIPv4 struct {
	VersionAndIHL          byte
	TypeOfService          byte
	TotalLength            uint16
	Identification         uint16
	FlagsAndFragmentOffset uint16
	TTL                    byte
	Protocol               byte
	HeaderChecksum         uint16
	SourceAddress          [4]byte
	DestinationAddress     [4]byte
	OptionsAndPadding      []byte
}
type PaquetTCP struct {
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	DataOffsetAndFlags   uint16
	WindowSize           uint16
	Checksum             uint16
	UrgentPointer        uint16
	OptionsAndPadding    []byte
}
type PaquetUDP struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}
type PaquetICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
}

type TrameComplete struct {
	TimeStamp   time.Time
	Trame       *Trame
	PaquetIPv4  *PaquetIPv4
	PaquetTCP   *PaquetTCP
	PaquetUDP   *PaquetUDP
	PaquetICMP  *PaquetICMP
	Application *DonneesApplication
}
type DonneesApplication struct {
	Data  []byte
	Texte string
}

func ScanLayers(interfaceName string, compteur int) map[string]TrameComplete {

	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	dictionnaire := make(map[string]TrameComplete)
	var i int = 0

	for packet := range packetSource.Packets() {
		i++

		rawBytes := packet.Data()
		var trame Trame
		var paquetIPv4 PaquetIPv4
		var paquetTCP PaquetTCP
		var paquetUDP PaquetUDP
		var donneesApp DonneesApplication
		var paquetICMP PaquetICMP

		copy(trame.DestinationMAC[:], rawBytes[0:6])
		copy(trame.SourceMAC[:], rawBytes[6:12])
		trame.EtherType = binary.BigEndian.Uint16(rawBytes[12:14])
		if trame.EtherType == 0x0800 { // Vérifie si c'est un paquet IPv4
			paquetIPv4.VersionAndIHL = rawBytes[14]
			paquetIPv4.TypeOfService = rawBytes[15]
			paquetIPv4.TotalLength = binary.BigEndian.Uint16(rawBytes[16:18])
			paquetIPv4.Identification = binary.BigEndian.Uint16(rawBytes[18:20])
			paquetIPv4.FlagsAndFragmentOffset = binary.BigEndian.Uint16(rawBytes[20:22])
			paquetIPv4.TTL = rawBytes[22]
			paquetIPv4.Protocol = rawBytes[23]
			paquetIPv4.HeaderChecksum = binary.BigEndian.Uint16(rawBytes[24:26])
			copy(paquetIPv4.SourceAddress[:], rawBytes[26:30])
			copy(paquetIPv4.DestinationAddress[:], rawBytes[30:34])

			ihl := paquetIPv4.VersionAndIHL & 0x0F // Extraire le IHL du paquet IPv4
			tailleHeaderIP := int(ihl) * 4         // mot de 4 octets

			if tailleHeaderIP > 20 && len(rawBytes) >= (14+tailleHeaderIP) {
				// On copie les options qui se trouvent entre la fin de l'IP fixe (octet 34) et la fin réelle du header IP
				paquetIPv4.OptionsAndPadding = make([]byte, tailleHeaderIP-20)
				copy(paquetIPv4.OptionsAndPadding, rawBytes[34:14+tailleHeaderIP])
			}
			paquetTCPStart := 14 + tailleHeaderIP
			if paquetIPv4.Protocol == 6 && len(rawBytes) >= (paquetTCPStart+20) { // TCP
				paquetTCP.SourcePort = binary.BigEndian.Uint16(rawBytes[paquetTCPStart : paquetTCPStart+2])
				paquetTCP.DestinationPort = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+2 : paquetTCPStart+4])
				paquetTCP.SequenceNumber = binary.BigEndian.Uint32(rawBytes[paquetTCPStart+4 : paquetTCPStart+8])
				paquetTCP.AcknowledgmentNumber = binary.BigEndian.Uint32(rawBytes[paquetTCPStart+8 : paquetTCPStart+12])
				paquetTCP.DataOffsetAndFlags = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+12 : paquetTCPStart+14])
				paquetTCP.WindowSize = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+14 : paquetTCPStart+16])
				paquetTCP.Checksum = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+16 : paquetTCPStart+18])
				paquetTCP.UrgentPointer = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+18 : paquetTCPStart+20])

			} else if paquetIPv4.Protocol == 17 && len(rawBytes) >= (paquetTCPStart+8) { // UDP
				paquetUDP.SourcePort = binary.BigEndian.Uint16(rawBytes[paquetTCPStart : paquetTCPStart+2])
				paquetUDP.DestinationPort = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+2 : paquetTCPStart+4])
				paquetUDP.Length = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+4 : paquetTCPStart+6])
				paquetUDP.Checksum = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+6 : paquetTCPStart+8])
			} else if paquetIPv4.Protocol == 1 { // ICMP
				paquetICMP.Type = rawBytes[paquetTCPStart]
				paquetICMP.Code = rawBytes[paquetTCPStart+1]
				paquetICMP.Checksum = binary.BigEndian.Uint16(rawBytes[paquetTCPStart+2 : paquetTCPStart+4])
			}

			if !reflect.ValueOf(paquetTCP).IsZero() {
				dataOffset := (paquetTCP.DataOffsetAndFlags >> 12) * 4 // DataOffset est en mots de 4 octets
				tailleHeaderTCP := int(dataOffset) * 4
				offsetDebutDonnees := paquetTCPStart + tailleHeaderTCP
				if len(rawBytes) > offsetDebutDonnees {
					donneesApp.Data = rawBytes[offsetDebutDonnees:]
					donneesApp.Texte = string(donneesApp.Data)
				}

			} else if !reflect.ValueOf(paquetUDP).IsZero() {
				offsetDebutDonnees := paquetTCPStart + 8 // Header UDP est toujours de 8 octets
				if len(rawBytes) > offsetDebutDonnees {
					donneesApp.Data = rawBytes[offsetDebutDonnees:]
					donneesApp.Texte = string(donneesApp.Data)
				}

			}
			cleUnique := fmt.Sprintf("paquet_%d", i)
			dictionnaire[cleUnique] = TrameComplete{
				TimeStamp:   packet.Metadata().Timestamp,
				Trame:       &trame,
				PaquetIPv4:  &paquetIPv4,
				PaquetTCP:   &paquetTCP,
				PaquetUDP:   &paquetUDP,
				PaquetICMP:  &paquetICMP,
				Application: &donneesApp,
			}
			fmt.Printf("Enregistré dans le dictionnaire ➔ %s (Type: 0x%04X)\n", cleUnique, trame.EtherType)
		}
		if compteur > 0 && i >= compteur {
			fmt.Printf("Scanning completed. Total packets processed: %d\n", compteur)
			break
		}

	}

	return dictionnaire
}
