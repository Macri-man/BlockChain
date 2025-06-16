package main

import (
	"log"
	"net/http"
)

func main() {
	// Initialize blockchain
	initBlockchain()

	// Register routes
	http.HandleFunc("/transaction", handlers.AddTransactionHandler)
	http.HandleFunc("/mine", handlers.MineBlockHandler)
	http.HandleFunc("/connect", handlers.ConnectPeerHandler)
	http.HandleFunc("/ws", handlers.HandlePeerConnections)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
