package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const difficulty = 4

type Block struct {
	Index        int
	Timestamp    string
	Transactions []Transaction
	PrevHash     string
	Hash         string
	Nonce        int
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
	newBlock.Timestamp = time.Now().UTC().Format(time.RFC3339)
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
