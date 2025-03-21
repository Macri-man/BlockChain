package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Block struct {
	Index        int
	Timestamp    string
	Transactions []Transaction
	PrevHash     string
	Hash         string
	Nonce        int
}

type Transaction struct {
	Sender    string
	Receiver  string
	Amount    float64
	Timestamp string
	Signature string
}

var Blockchain []Block
var TransactionPool []Transaction
var mutex = &sync.Mutex{}
var difficulty = 4

// Peers
var peers = make(map[*websocket.Conn]bool)
var peerMutex = &sync.Mutex{}
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func IsBlockchainValid() bool {
	for i := 1; i < len(Blockchain); i++ {
		previousBlock := Blockchain[i-1]
		currentBlock := Blockchain[i]
		// Check if the current block's previous hash matches the previous block's hash
		if currentBlock.PrevHash != previousBlock.Hash {
			return false
		}
		// Check if the current block's hash is correctly calculated
		if currentBlock.Hash != CalculateHash(currentBlock) {
			return false
		}
	}
	return true
}

type Transaction struct {
	Sender    string
	Receiver  string
	Amount    float64
	Timestamp string
	Signature []byte
}

func SignTransaction(transaction *Transaction, privateKey *ecdsa.PrivateKey) {
	// Sign the transaction
	hash := sha256.New()
	hash.Write([]byte(transaction.Sender + transaction.Receiver + fmt.Sprintf("%f", transaction.Amount)))
	transaction.Signature, _ = ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
}

func VerifyTransactionSignature(transaction *Transaction, publicKey *ecdsa.PublicKey) bool {
	// Verify the transaction signature
	hash := sha256.New()
	hash.Write([]byte(transaction.Sender + transaction.Receiver + fmt.Sprintf("%f", transaction.Amount)))
	return ecdsa.Verify(publicKey, hash.Sum(nil), transaction.Signature)
}

// Add a maximum transaction pool size
var maxTransactionPoolSize = 100

func AddTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid transaction", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	if len(TransactionPool) < maxTransactionPoolSize {
		TransactionPool = append(TransactionPool, tx)
	} else {
		http.Error(w, "Transaction pool full", http.StatusForbidden)
		mutex.Unlock()
		return
	}
	mutex.Unlock()

	BroadcastTransaction(tx)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tx)
}


func CalculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + block.PrevHash + strconv.Itoa(block.Nonce)
	for _, tx := range block.Transactions {
		record += tx.Sender + tx.Receiver + fmt.Sprintf("%f", tx.Amount)
	}
	hash := sha256.Sum256([]byte(record))
	return fmt.Sprintf("%x", hash)
}

func GenerateBlock(prevBlock Block, transactions []Transaction) Block {
	var newBlock Block
	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = time.Now().String()
	newBlock.Transactions = transactions
	newBlock.PrevHash = prevBlock.Hash
	newBlock.Nonce = 0

	for {
		newBlock.Hash = CalculateHash(newBlock)
		if newBlock.Hash[:difficulty] == strings.Repeat("0", difficulty) {
			break
		}
		newBlock.Nonce++
	}

	return newBlock
}

func MineBlock(miner string) {
	mutex.Lock()
	defer mutex.Unlock()

	if len(TransactionPool) == 0 {
		return
	}

	rewardTx := Transaction{Sender: "network", Receiver: miner, Amount: rand.Float64() * 10}
	TransactionPool = append(TransactionPool, rewardTx)

	newBlock := GenerateBlock(Blockchain[len(Blockchain)-1], TransactionPool)
	Blockchain = append(Blockchain, newBlock)
	TransactionPool = []Transaction{}
	SaveBlockchain()

	BroadcastBlock(newBlock)
}

func syncBlockchainFromPeer(conn *websocket.Conn) {
	// Request the entire blockchain from the connected peer
	requestMessage := map[string]string{"type": "get_blockchain"}
	conn.WriteJSON(requestMessage)

	// Listen for the blockchain response
	_, message, _ := conn.ReadMessage()
	var receivedBlockchain []Block
	json.Unmarshal(message, &receivedBlockchain)

	// Validate and append the received blockchain if valid
	if IsBlockchainValid() {
		mutex.Lock()
		Blockchain = append(Blockchain, receivedBlockchain...)
		SaveBlockchain()
		mutex.Unlock()
	}
}


func SaveBlockchain() {
	data, _ := json.MarshalIndent(Blockchain, "", "  ")
	os.WriteFile("blockchain.json", data, 0644)
}

func BroadcastTransaction(tx Transaction) {
	peerMutex.Lock()
	defer peerMutex.Unlock()
	message, _ := json.Marshal(tx)
	for peer := range peers {
		peer.WriteMessage(websocket.TextMessage, message)
	}
}

func BroadcastBlock(block Block) {
	peerMutex.Lock()
	defer peerMutex.Unlock()
	message, _ := json.Marshal(block)
	for peer := range peers {
		peer.WriteMessage(websocket.TextMessage, message)
	}
}

func AddTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var tx Transaction
	if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
		http.Error(w, "Invalid transaction", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	TransactionPool = append(TransactionPool, tx)
	mutex.Unlock()

	BroadcastTransaction(tx)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tx)
}

func MineBlockHandler(w http.ResponseWriter, r *http.Request) {
	MineBlock("04a5b1...")
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

	peerMutex.Lock()
	peers[conn] = true
	peerMutex.Unlock()
	go listenToPeer(conn)
	w.WriteHeader(http.StatusOK)
}

func handlePeerConnections(w http.ResponseWriter, r *http.Request) {
	conn, _ := upgrader.Upgrade(w, r, nil)
	peerMutex.Lock()
	peers[conn] = true
	peerMutex.Unlock()

	for _, tx := range TransactionPool {
		conn.WriteJSON(tx)
	}
	go listenToPeer(conn)
}

func listenToPeer(conn *websocket.Conn) {
	defer func() {
		peerMutex.Lock()
		delete(peers, conn)
		peerMutex.Unlock()
		conn.Close()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var tx Transaction
		if err := json.Unmarshal(message, &tx); err == nil {
			mutex.Lock()
			TransactionPool = append(TransactionPool, tx)
			mutex.Unlock()
			continue
		}

		var newBlock Block
		if err := json.Unmarshal(message, &newBlock); err == nil {
			mutex.Lock()
			Blockchain = append(Blockchain, newBlock)
			SaveBlockchain()
			mutex.Unlock()
			continue
		}
	}
}

func main() {
	genesisBlock := Block{Index: 0, Timestamp: time.Now().String(), Hash: "0"}
	Blockchain = append(Blockchain, genesisBlock)
	SaveBlockchain()

	http.HandleFunc("/transaction", AddTransactionHandler)
	http.HandleFunc("/mine", MineBlockHandler)
	http.HandleFunc("/connect", ConnectPeerHandler)
	http.HandleFunc("/ws", handlePeerConnections)

	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
