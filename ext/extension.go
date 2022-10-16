package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	// "github.com/osquery/osquery-go"
	// "github.com/osquery/osquery-go/plugin/table"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	pcapFile string = "./out.pcap"
	handle   *pcap.Handle
	err      error
)

func main() {

	socket := flag.String("socket", "", "Path to osquery socket file")
	flag.Parse()
	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("pcap", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("pcap", FoobarColumns(), FoobarGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// FoobarColumns returns the columns that our table will return.
func FoobarColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("packet_time"),
		table.TextColumn("Layer Type"),
		table.TextColumn("Layer Contents"),
	}
}

// FoobarGenerate will be called whenever the table is queried. It should return
// a full table scan.
func FoobarGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var res_map = []map[string]string{}

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in files
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// fmt.Println(packet)
		// res_map = append(res_map, map[string]string{"packets": packet.String()})
		// fmt.Print(/)
		var packet_date string = packet.Metadata().Timestamp.String()
		for _, layer := range packet.Layers() {
			var layertype string = layer.LayerType().String()
			var layercontents string = fmt.Sprintf("%v", layer.LayerContents())
			fmt.Println(layertype)
			fmt.Println(layercontents)
			res_map = append(res_map, map[string]string{"packet_time": packet_date, "Layer Type": layertype, "Layer Contents": layercontents})
		}
	}

	return res_map, nil
}
