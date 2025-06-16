package main

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

var peers = make(map[*websocket.Conn]bool)
var peerMutex = &sync.Mutex{}

func AddPeer(conn *websocket.Conn) {
	peerMutex.Lock()
	peers[conn] = true
	peerMutex.Unlock()
}

func RemovePeer(conn *websocket.Conn) {
	peerMutex.Lock()
	delete(peers, conn)
	peerMutex.Unlock()
}

func BroadcastTransaction(tx Transaction) {
	peerMutex.Lock()
	defer peerMutex.Unlock()
	message, err := json.Marshal(tx)
	if err != nil {
		log.Printf("Error marshaling transaction: %v", err)
		return
	}
	for peer := range peers {
		if err := peer.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Printf("Error sending transaction to peer: %v", err)
		}
	}
}

func BroadcastBlock(block Block) {
	peerMutex.Lock()
	defer peerMutex.Unlock()
	message, err := json.Marshal(block)
	if err != nil {
		log.Printf("Error marshaling block: %v", err)
		return
	}
	for peer := range peers {
		if err := peer.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Printf("Error sending block to peer: %v", err)
		}
	}
}
