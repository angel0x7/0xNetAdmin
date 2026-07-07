package internal

import (
	"encoding/binary"
	"fmt"
	"log"
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

type TrameComplete struct {
	TimeStamp  time.Time
	Trame      *Trame
	PaquetIPv4 *PaquetIPv4
	PaquetTCP  *PaquetTCP
	PaquetUDP  *PaquetUDP
}

func ScanLayers(interfaceName string, compteur int) map[string]TrameComplete {

	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	dictionnaire := make(map[string]TrameComplete)
	compteur = 0
	for packet := range packetSource.Packets() {
		compteur++

		rawBytes := packet.Data()
		var trame Trame
		var paquetIPv4 PaquetIPv4
		var paquetTCP PaquetTCP
		var paquetUDP PaquetUDP

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

			paquetTCP.SourcePort = binary.BigEndian.Uint16(rawBytes[34:36])
			paquetTCP.DestinationPort = binary.BigEndian.Uint16(rawBytes[36:38])
			paquetTCP.SequenceNumber = binary.BigEndian.Uint32(rawBytes[38:42])
			paquetTCP.AcknowledgmentNumber = binary.BigEndian.Uint32(rawBytes[42:46])
			paquetTCP.WindowSize = binary.BigEndian.Uint16(rawBytes[46:48])
			paquetTCP.Checksum = binary.BigEndian.Uint16(rawBytes[48:50])
			paquetTCP.UrgentPointer = binary.BigEndian.Uint16(rawBytes[50:52])

			paquetUDP.SourcePort = binary.BigEndian.Uint16(rawBytes[34:36])
			paquetUDP.DestinationPort = binary.BigEndian.Uint16(rawBytes[36:38])
			paquetUDP.Length = binary.BigEndian.Uint16(rawBytes[38:40])
			paquetUDP.Checksum = binary.BigEndian.Uint16(rawBytes[40:42])

			ihl := paquetIPv4.VersionAndIHL & 0x0F
			tailleHeaderIP := int(ihl) * 4

			if tailleHeaderIP > 20 && len(rawBytes) >= (14+tailleHeaderIP) {
				// On copie les options qui se trouvent entre la fin de l'IP fixe (octet 34) et la fin réelle du header IP
				paquetIPv4.OptionsAndPadding = make([]byte, tailleHeaderIP-20)
				copy(paquetIPv4.OptionsAndPadding, rawBytes[34:14+tailleHeaderIP])
			}
			cleUnique := fmt.Sprintf("paquet_%d", compteur)
			dictionnaire[cleUnique] = TrameComplete{
				Trame:      &trame,
				PaquetIPv4: &paquetIPv4,
				PaquetTCP:  &paquetTCP,
				PaquetUDP:  &paquetUDP,
			}
			fmt.Printf("Enregistré dans le dictionnaire ➔ %s (Type: 0x%04X)\n", cleUnique, trame.EtherType)
		}
		if compteur >= 100 {
			fmt.Printf("Scanning completed. Total packets processed: %d\n", compteur)
			break
		}

	}

	return dictionnaire
}
