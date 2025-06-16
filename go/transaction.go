package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/rand"
)

type Transaction struct {
	Sender    string
	Receiver  string
	Amount    float64
	Timestamp string
	Signature []byte
}

func SignTransaction(transaction *Transaction, privateKey *ecdsa.PrivateKey) error {
	hash := sha256.New()
	hash.Write([]byte(transaction.Sender + transaction.Receiver + fmt.Sprintf("%f", transaction.Amount)))
	signature, err := ecdsa.Sign(rand.Reader, privateKey, hash.Sum(nil))
	if err != nil {
		return err
	}
	transaction.Signature = signature
	return nil
}

func getTransactionHash(transaction *Transaction) []byte {
	data := fmt.Sprintf("%s%s%f%s", transaction.Sender, transaction.Receiver, transaction.Amount, transaction.Timestamp)
	hash := sha256.New()
	hash.Write([]byte(data))
	return hash.Sum(nil)
}

func VerifyTransactionSignature(transaction *Transaction, publicKey *ecdsa.PublicKey) bool {
	hash := sha256.New()
	hash.Write([]byte(transaction.Sender + transaction.Receiver + fmt.Sprintf("%f", transaction.Amount)))
	return ecdsa.Verify(publicKey, hash.Sum(nil), transaction.Signature)
}
