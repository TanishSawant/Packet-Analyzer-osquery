package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var (
		pcapFile string = "./out.pcap"
		handle   *pcap.Handle
		err      error
	)

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in files
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		for _, layer := range packet.Layers() {
			fmt.Println(layer.LayerType())
			fmt.Println(layer.LayerContents())
		}

		// fmt.Println(packet.Metadata().Timestamp.UTC())
		// res_map = append(res_map, map[string]string{"packets": packet.String()})
		// fmt.Print(/)
	}
}
