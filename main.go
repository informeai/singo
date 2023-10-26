package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

func verify(signature, publicKeyBase64, body string) bool {
	public_key, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		fmt.Printf("[ERROR.VERIFY.SIGNATURE]: %v\n", err)
		return false
	}
	block, _ := pem.Decode(public_key)
	if block == nil {
		return false
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("[ERROR.VERIFY.SIGNATURE]: %v\n", err)
		return false
	}
	pk := genericPublicKey.(*ecdsa.PublicKey)

	bSign, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Printf("[ERROR.VERIFY.SIGNATURE]: %v\n", err)
		return false
	}
	hash := sha256.Sum256([]byte(body))

	return ecdsa.VerifyASN1(pk, hash[:], bSign)
}

func sign(private_key_base64, body string) (string, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(private_key_base64)
	if err != nil {
		return "", err
	}

	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return "", errors.New("no pem block found")
	}

	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(body))
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

var (
	signature        string
	privateKeyBase64 string
	publicKeyBase64  string
	body             string
)

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("DESCRIPTION:\nUtility for create and verify signature\nUSAGE:\nsingo [options] [params]\nOPTIONS:\n\tverify -> verify signature\n\tsign -> create signature\nPARAMS:\n--signature\n--private-key-base64\n--public-key-base64\n--body\nEXAMPLES:\nsingo sign --private-key-base64 [PRIVATE BASE64] --body [MESSAGE]\nsingo verify --signature [SIGNATURE] --public-key-base64 [PUBLIC BASE64] --body [MESSAGE]\n")
		os.Exit(0)
	}
	setFlags := flag.NewFlagSet("", flag.ContinueOnError)
	setFlags.StringVar(&signature, "signature", "", "signature string")
	setFlags.StringVar(&privateKeyBase64, "private-key-base64", "", "private key base64")
	setFlags.StringVar(&publicKeyBase64, "public-key-base64", "", "public key base64")
	setFlags.StringVar(&body, "body", "", "body message string")
	err := setFlags.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}
	switch os.Args[1] {
	case "verify":
		isVerified := verify(signature, publicKeyBase64, body)
		fmt.Printf("\nISVERIFIED: %v\n", isVerified)
		break
	case "sign":
		sign, err := sign(privateKeyBase64, body)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
			break
		}
		fmt.Printf("\nSIGNATURE: %v\n", sign)
		break
	default:
		fmt.Printf("DESCRIPTION:\nUtility for create and verify signature\nUSAGE:\nsingo [options] [params]\nOPTIONS:\n\tverify -> verify signature\n\tsign -> create signature\nPARAMS:\n--signature\n--private-key-base64\n--public-key-base64\n--body\nEXAMPLES:\nsingo sign --private-key-base64 [PRIVATE BASE64] --body [MESSAGE]\nsingo verify --signature [SIGNATURE] --public-key-base64 [PUBLIC BASE64] --body [MESSAGE]\n")
		os.Exit(0)
	}
}
