package contract

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"

	"github.com/xuperchain/xuper-sdk-go/config"
	"github.com/xuperchain/xuperchain/core/pb"
	"github.com/xuperchain/xuperchain/core/crypto/sign"
	"github.com/xuperchain/xuperchain/core/crypto/account"
	"github.com/xuperdata/teesdk"
)

// EncryptArgs call the TEE App to encrypt the value of the args
// add publickey and signature for authentication
func (c *WasmContract) EncryptArgs(svn uint32,args map[string]string) (string, error) {
	plainJson, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	// sign the following data
	sigContent := []byte("encrypt" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(teesdk.FuncCaller{
		Method: "encrypt",
		Args: string(plainJson),
		Svn: svn,
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	newCipher, err := c.tfc.Submit("xchaintf", string(data))
	return string(newCipher), err
}

// DecryptArgs call the TEE App to decrypt the value of the args
// add publickey and signature for authentication
func (c *WasmContract) DecryptArgs(svn uint32,args map[string]string) (string, error) {
	plainJson, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	// sign the following data
	sigContent := []byte("decrypt" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(teesdk.FuncCaller{
		Method: "decrypt",
		Args: string(plainJson),
		Svn: svn,
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	newPlain, err := c.tfc.Submit("xchaintf", string(data))
	return string(newPlain), err
}

// QueryWasmContractPlain decrypts QueryWasmContract result to get plaintext value
func (c *WasmContract) DecryptResponse (responseCipher *pb.InvokeRPCResponse) (*pb.InvokeRPCResponse, error) {
	// 取出 key和对应的密文
	respArgs := make(map[string]string)
	for _,res := range responseCipher.GetResponse().GetResponse() {
		respArgs["key"] = string(res)
	}

	// 解密密文得到key和对应明文
	commConfig := config.GetInstance()
	decryptArgs, err := c.DecryptArgs(commConfig.TC.Svn, respArgs)
	if err != nil {
		log.Println("DecryptArgs error,", err)
		return nil, err
	}

	// decryptArgs is key:plain
	args := make(map[string]string)
	err = json.Unmarshal([]byte(decryptArgs), &args)
	if err != nil {
		return nil, err
	}

	// 解密后的明文覆盖原有的密文kv，返回的是明文
	plain := args["key"]
	decodeValueByte, err := base64.StdEncoding.DecodeString(plain)
	if err != nil {
		return nil, err
	}
	resp := responseCipher.GetResponse().GetResponse()
	resp[0] = resp[0][:len(decodeValueByte)]
	copy(resp[0], decodeValueByte)
	responseCipher.GetResponse().Response = resp

	return responseCipher, nil
}

func (c *WasmContract) EncryptWasmArgs(args map[string]string) (map[string]string, error) {
	// preExe
	commConfig := config.GetInstance()
	// TODO fix bug
	if commConfig.TC.Enable {
		encryptedArgs, err := c.EncryptArgs(commConfig.TC.Svn, args)
		if err != nil {
			log.Println("EncryptArgs error,", err)
			return nil, err
		}
		args = map[string]string{}
		err = json.Unmarshal([]byte(encryptedArgs), &args)
		if err != nil {
			return nil, err
		}
		return args, nil
	}
	return args, nil
}

// get commitment for authorized user
func (c *WasmContract) GetAuthResp(cipher, user string) (map[string]string, error) {
	commConfig := config.GetInstance()
	args := map[string]string {
		"ciphertext": cipher,
		"to": user,
		"kind": "commitment",
	}
	plainJson, err := json.Marshal(args)
	if err != nil {
		log.Println("GetAuthResp error,", err)
		return nil, err
	}
	// sign the following data
	sigContent := []byte("authorize" + string(plainJson))
	pubHex := GetPubkeyHexFromJson(c.Account.PublicKey)
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	// put pubkey and signature into request body
	data, err := json.Marshal(teesdk.FuncCaller{
		Method: "authorize",
		Args: string(plainJson),
		Svn: commConfig.TC.Svn,
		Address: c.Account.Address,
		PublicKey: pubHex,
		Signature: sigHex,
	})
	authResponse, err := c.tfc.Submit("xchaintf", string(data))
	if err != nil {
		log.Println("GetAuthResp error,", err)
		return nil, err
	}
	err = json.Unmarshal([]byte(authResponse), &args)
	if err != nil {
		return nil, err
	}
	return args, nil
}

func GetPubkeyHexFromJson(publicStr string) string{
	pubkey,_ := account.GetEcdsaPublicKeyFromJSON([]byte(publicStr))
	pubStr := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	return hex.EncodeToString(pubStr)
}

func SignEcdsaHex(prvkeyStr string, msg []byte) string {
	prvkey,_ := account.GetEcdsaPrivateKeyFromJSON([]byte(prvkeyStr))
	hash := sha256.Sum256(msg)
	sig,_ := sign.SignECDSA(prvkey, hash[:])
	return hex.EncodeToString(sig)
}

// get signature for authorize request
func (c *WasmContract) SignAuthReq(cipher, to, kind string) (string, error) {
	args := map[string]string {
		"ciphertext": cipher,
		"to": to,
		"kind": kind,
	}
	plainJson, err := json.Marshal(args)
	// sign the following data
	if err != nil {
		log.Println("SignAuthReq error,", err)
		return "", err
	}
	sigContent := []byte("authorize" + string(plainJson))
	sigHex := SignEcdsaHex(c.Account.PrivateKey, sigContent)
	return sigHex, nil
}