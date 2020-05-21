package contract

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/xuperchain/xuperchain/core/crypto/account"
	"github.com/xuperchain/xuperchain/core/crypto/utils"
	"github.com/xuperdata/teesdk/paillier"
	"io/ioutil"
	"strings"
)

func (c *WasmContract) GenPaillierKeys(secbit int64) (string, error) {
	keyGenArgs := map[string]int64{
		"secbit": secbit,
	}
	plainJson, err := json.Marshal(keyGenArgs)
	if err != nil {
		return "", err
	}
	// sign the following data
	sigContent := []byte("PaillierKeyGen" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(paillier.FuncCaller{
		Method: "PaillierKeyGen",
		Args: string(plainJson),
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	newCipher, err := c.tc.Submit("paillier", string(data))
	return string(newCipher), err
}

// EncryptArgs call the paillier to encrypt the value of the args
// add publickey and signature for authentication
func (c *WasmContract) EncryptPaillierArgs(args map[string]string) (string, error) {
	plainJson, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	// sign the following data
	sigContent := []byte("PaillierEnc" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(paillier.FuncCaller{
		Method: "PaillierEnc",
		Args: string(plainJson),
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	newCipher, err := c.tc.Submit("paillier", string(data))
	return string(newCipher), err
}

// DecryptArgs call the paillier to decrypt the value of the args
// add publickey and signature for authentication
func (c *WasmContract) DecryptPaillierArgs(args map[string]string) (string, error) {
	plainJson, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	// sign the following data
	sigContent := []byte("PaillierDec" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(paillier.FuncCaller{
		Method: "PaillierDec",
		Args: string(plainJson),
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	newPlain, err := c.tc.Submit("paillier", string(data))
	return string(newPlain), err
}

// get commitment for authorized user
// commitment = ecdsaSign(hash(cipher,user))
func (c *WasmContract) GetPaillierAuth(cipher, user string) (string, error) {
	prvkey,err := account.GetEcdsaPrivateKeyFromJSON([]byte(c.Account.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("get cedsa private key from json error: %v", err)
	}
	msg := cipher + user
	hash := sha256.Sum256([]byte(msg))
	pk := prvkey.PublicKey
	pubkey := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	r, s, err := ecdsa.Sign(rand.Reader, prvkey, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign error: %v", err)
	}
	sigRS := utils.ECDSASignature{r, s}
	sig, err := asn1.Marshal(sigRS)
	if err != nil {
		return "", fmt.Errorf("marshal signature error: %v", err)
	}

	commitment := make([]byte, 65+len(sig))
	copy(commitment[0:], pubkey)
	copy(commitment[65:], sig)
	return base64.RawStdEncoding.EncodeToString(commitment), nil
}

// save private key to file
func SavePrvKey(path string, filename string, password string, prvkey string) error {
	if strings.LastIndex(path, "/") != len([]rune(path))-1 {
		path = path + "/"
	}

	// ciphertext = aesEnc(hash(pwd), prvkey)
	realKey := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(realKey[:])
	if err != nil {
		return fmt.Errorf("get aes new cipher error: %v", err)
	}
	blockSize := block.BlockSize()
	originalData := BytesPKCS5Padding([]byte(prvkey), blockSize)
	blockMode := cipher.NewCBCEncrypter(block, realKey[:blockSize])
	ciphertext := make([]byte, len(originalData))
	blockMode.CryptBlocks(ciphertext, originalData)

	err = ioutil.WriteFile(path+filename, ciphertext, 0666)
	if err != nil {
		return fmt.Errorf("Export private key file failed, the err is %v", err)
	}
	return nil
}

// save public key to file
func SavePubKey(path string, filename string, pubkey string) error {
	if strings.LastIndex(path, "/") != len([]rune(path))-1 {
		path = path + "/"
	}

	err := ioutil.WriteFile(path+filename, []byte(pubkey), 0666)
	if err != nil {
		return fmt.Errorf("Export public key file failed, the err is %v", err)
	}
	return nil
}

func BytesPKCS5Padding(cipherData []byte, blockSize int) []byte {
	padLength := blockSize - len(cipherData)%blockSize
	padData := bytes.Repeat([]byte{byte(padLength)}, padLength)
	return append(cipherData, padData...)
}
