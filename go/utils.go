package main

import (
	"encoding/json"
	"log"
	"os"
)

func IsBlockchainValid() bool {
	for i := 1; i < len(Blockchain); i++ {
		previousBlock := Blockchain[i-1]
		currentBlock := Blockchain[i]
		if currentBlock.PrevHash != previousBlock.Hash {
			return false
		}
		if currentBlock.Hash != CalculateHash(currentBlock) {
			return false
		}
	}
	return true
}

func SaveBlockchain() {
	data, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling blockchain: %v", err)
	}

	err = os.WriteFile("blockchain.json", data, 0644)
	if err != nil {
		log.Fatalf("Error writing blockchain to file: %v", err)
	}
}
