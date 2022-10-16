package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {

	socket := flag.String("socket", "", "Path to osquery socket file")
	flag.Parse()
	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("tracert", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("tracert", FoobarColumns(), FoobarGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}

	// fmt.Println(output)

}

func FoobarColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Route"),
	}
}

func FoobarGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var res_map = []map[string]string{}

	app := "tracert"

	// arg0 := "11.1.0.1"
	arg0 := "google.com"
	// arg1 := "Hello world"
	// arg2 := "\n\tfrom"
	// arg3 := "golang"

	cmd := exec.Command(app, arg0)
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
	}
	output := string(stdout)
	// Print the output
	for _, line := range strings.Split(output, "\n") {
		// fmt.Println(k)
		fmt.Println("#")
		fmt.Println(string(line))
		res_map = append(res_map, map[string]string{"Route": string(line)})
	}

	return res_map, nil
}
