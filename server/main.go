package main

import (
	"log"
	"os"
)

func main() {
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatal(err)
	}
	startHTTPServer()
	select {} // Keep running
}
