package main
import (
    "crypto/rand"
	// "io"
	// "crypto/sha256"
    // "crypto/rsa"
    "crypto/ecdsa"
    "crypto/x509"
    "errors"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	// "io/ioutil"
)
func DecodeAllBlocks(pemBytes []byte) map[string]*pem.Block {
	blocksMap := make(map[string]*pem.Block)

	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break // Nenhum bloco PEM restante
		}

		// Armazena o bloco PEM decodificado no mapa
		blocksMap[block.Type] = block

		pemBytes = rest
	}

	return blocksMap
}
func sign(private_key_base64, content string) (string, error) {
	// Decodificar a chave PEM de base64
	pemBytes, err := base64.StdEncoding.DecodeString(private_key_base64)
	if err != nil {
		panic("Erro na decodificação de base64")
	}


	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return "", errors.New("No pem block found")
	}

	// Parse da chave ECDSA
	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes) // ParseRsaPrivateKeyFromPemStr(string())
	if err != nil {
		fmt.Println("ERRO NA PARSE")
		//Se o parsing falhar, tente decodificar usando btcec
		
			// log.Fatalf("Falha ao decodificar a chave privada: %v", err)
			panic(err)
		
	}

	// hash := sha256.Sum256([]byte(content))

	// Assinar a hash usando a chave privada carregada do PEM
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, []byte(content))
	if err != nil {
		fmt.Println("ERRO NA SIGN")
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}


func verify(public_key_base64, content, signed string) bool {
	public_key, err := base64.StdEncoding.DecodeString(public_key_base64)
    if err != nil {
        fmt.Println(err)
        return false
    }

	block, _ := pem.Decode(public_key)
	if block == nil {
		return false
	}
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}
	pk := genericPublicKey.(*ecdsa.PublicKey)


	bSign, err := base64.StdEncoding.DecodeString(signed)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(pk, []byte(content), bSign)
}

// apikey key - horario
func main() {
  	private_key_base64 := "PAST HERE YOUR PRIVATE KEY BASE64"
  	public_key_base64 := "PAST HERE YOUR PUBLIC KEY BASE64"
	content := "CONTEUDO ALEATORIO"
	signed, err := sign(private_key_base64, content)
	if err != nil {
		fmt.Println(err)
		return
  	}

  	fmt.Printf("%v", signed)
	// message = bearertoken + ":" + request-timestamp + ":" + bodyString.Base64
	if verify(public_key_base64, content, signed) {
		fmt.Println("verificado")
		return
	}

	fmt.Println("não verificado")

}