package main

import (
	"log"
	"net/http"
)

func startHTTPServer() {
	httpHandlers() // Теперь здесь НЕТ дублирующей регистрации /static/
	go func() {
		log.Println("Starting HTTP server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal(err)
		}
	}()
}
