package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/websocket"
)

func AddTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var tx blockchain.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid transaction", http.StatusBadRequest)
		return
	}

	blockchain.TransactionPool = append(blockchain.TransactionPool, tx)
	blockchain.BroadcastTransaction(tx)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tx)
}

func MineBlockHandler(w http.ResponseWriter, r *http.Request) {
	blockchain.MineBlock("minerID")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Block mined!"})
}

func ConnectPeerHandler(w http.ResponseWriter, r *http.Request) {
	peerAddr := r.URL.Query().Get("peer")
	conn, _, err := websocket.DefaultDialer.Dial(peerAddr, nil)
	if err != nil {
		http.Error(w, "Failed to connect", http.StatusInternalServerError)
		return
	}

	blockchain.AddPeer(conn)
	go listenToPeer(conn)

	w.WriteHeader(http.StatusOK)
}

func HandlePeerConnections(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	blockchain.AddPeer(conn)

	for _, tx := range blockchain.TransactionPool {
		conn.WriteJSON(tx)
	}
	go listenToPeer(conn)
}

func listenToPeer(conn *websocket.Conn) {
	defer func() {
		blockchain.RemovePeer(conn)
		conn.Close()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var tx blockchain.Transaction
		if err := json.Unmarshal(message, &tx); err == nil {
			blockchain.TransactionPool = append(blockchain.TransactionPool, tx)
			continue
		}

		var newBlock blockchain.Block
		if err := json.Unmarshal(message, &newBlock); err == nil {
			blockchain.Blockchain = append(blockchain.Blockchain, newBlock)
			blockchain.SaveBlockchain()
			continue
		}
	}
}
