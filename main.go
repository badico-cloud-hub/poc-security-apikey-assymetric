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

	hash := sha256.Sum256([]byte(content))
	// Assinar a hash usando a chave privada carregada do PEM
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
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

	hash := sha256.Sum256([]byte(content))
	return ecdsa.VerifyASN1(pk, hash[:], bSign)
}

// apikey key - horario
func main() {
  	private_key_base64 := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUs3YTBxTHd5YzRWRDZMTE5qRWMyTUIrK2NpbTBBVkRobjNWWjBNbHRubTlvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFajBzc3dmNkxGN0EvRWZ3ZXhyZVpWZ292OE1kOFdCVU9mazJUKzlQcFpjV0ZOSWFTaXZyZAppc0hVSHRiaGxXN0Y0U3E0di9JcDE2ekFqTFYzU2dMeVRnPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
  	public_key_base64 := "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFajBzc3dmNkxGN0EvRWZ3ZXhyZVpWZ292OE1kOApXQlVPZmsyVCs5UHBaY1dGTklhU2l2cmRpc0hVSHRiaGxXN0Y0U3E0di9JcDE2ekFqTFYzU2dMeVRnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
	content := "CONTEUDO ALEATORIO"
	signed, err := sign(private_key_base64, content)
	if err != nil {
		fmt.Println(err)
		return
  	}

  	// fmt.Printf("%v", signed)
	// message = bearertoken + ":" + request-timestamp + ":" + bodyString.Base64


	fmt.Println("não verificado")

}