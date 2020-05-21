package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xuperchain/xuper-sdk-go/account"
	"github.com/xuperchain/xuper-sdk-go/contract"
	"github.com/xuperdata/teesdk/paillier/xchain_plugin/pb"
)

var (
	secbit = 1024
	paillierPrvkey = ""
	paillierPubkey = ""
	plaintext1 = "15"
	plaintext2 = "20"
	scalar = "10"
	ciphertext1 = ""
	ciphertext2 = ""
	cipherAdd = ""
	cipherMul = ""
	addition = "35"
	scalarMul = "150"

	data1 = "1"
	data2 = "2"
	dataAdd = "3"
	dataMul = "4"

	paillierPrvPath = "/root/"
	paillierPrvFile = "paillierPrv.key"
	password = "123456"
)

// define blockchain node and blockchain name
var (
	language = 1
	node         = "localhost:37101"
	bcname       = "xuper"
	codePath 	 = "example/contract_code/paillier.wasm"

	contractAcc = "XC1111111111111122@xuper"
	// generate user's account and save private.key to ./newkeys
	user        = "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	// create an account controlled by user
	userAcc     = "XC1111111111111111@xuper"
	contractName = "paillier"
	transactionId = ""
)

func testAccount() {
	log.Printf("start testAccount......")
	if _, err := os.Stat("./keys"); err != nil && os.IsNotExist(err) {
	} else {
		println("existed, pass")
		return
	}

	acc, err := account.CreateAccount(1, 1)
	if err != nil {
		fmt.Printf("create account error: %v\n", err)
		panic(err)
	}
	fmt.Println("hello, Mnemonic: ", acc.Mnemonic)

	// retrieve the account by mnemonics
	acc, err = account.RetrieveAccount(acc.Mnemonic, 1)
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
		panic(err)
	}
	fmt.Printf("RetrieveAccount: to %v\n", acc)

	// create an account, then encrypt using password and save it to a file
	acc, err = account.CreateAndSaveAccountToFile("./keys", "123", 1, 1)
	if err != nil {
		fmt.Printf("createAndSaveAccountToFile err: %v\n", err)
		panic(err)
	}
	fmt.Printf("CreateAndSaveAccountToFile: %v\n", acc)

	// get the account from file, using password decrypt
	acc, err = account.GetAccountFromFile("keys/", "123")
	if err != nil {
		fmt.Printf("getAccountFromFile err: %v\n", err)
		panic(err)
	}
	fmt.Printf("getAccountFromFile: %v\n", acc)
	log.Printf("finish testAccount......\n\n")
	return
}

func usingAccount() (*account.Account, error) {
	// load your account from the private key and secure code you download from xuper.baidu.com
	// Note that put the downloaded private key file at path "./keys/private.key"
	acc, err := account.GetAccountFromFile("./keys/", "123")
	if err != nil {
		return nil, fmt.Errorf("create account error: %v\n", err)
	}

	return acc, nil
}

func testDeployWasmContract() {
	log.Printf("start testDeployWasmContract......\n")
	acc, err := usingAccount()
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
		panic(err)
	}

	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

	// deploy wasm contract
	txid, err := wasmContract.DeployWasmContract(nil, codePath, "c")
	if err != nil {
		log.Printf("DeployWasmContract err: %v", err)
		panic(err)
	}
	fmt.Printf("DeployWasmContract txid: %v\n", txid)
	log.Printf("finish testDeployWasmContract......\n\n")
	return
}

func testKeyGen() {
	log.Printf("start keygen......\n")
	acc, err := usingAccount()
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
		panic(err)
	}

	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

	keyArgs, err := wasmContract.GenPaillierKeys(int64(secbit))
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
    var keyMap pb.KeyGenOutputs
	json.Unmarshal([]byte(keyArgs), &keyMap)
	paillierPrvkey = keyMap.PrivateKey
	paillierPubkey = keyMap.PublicKey
	err = contract.SavePrvKey(paillierPrvPath, paillierPrvFile, password, paillierPrvkey)
	if err != nil {
		log.Printf("save paillier private key failed, err: %v", err)
		os.Exit(-1)
	}

	log.Printf("keygen args: %s\n", keyArgs)
	log.Printf("privatekey: %s\n", paillierPrvkey)
	log.Printf("publickey: %s\n", paillierPubkey)
	log.Printf("...... keygen finished ......\n\n")
	return
}

func testEnc() {
	log.Printf("start paillierEnc......\n")
	acc, err := usingAccount()
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
		panic(err)
	}

	plainArgs := map[string]string{
		"message": plaintext1,
		"publicKey": paillierPubkey,
	}
	plainArgs2 := map[string]string{
		"message": plaintext2,
		"publicKey": paillierPubkey,
	}
	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

	encArgs, err := wasmContract.EncryptPaillierArgs(plainArgs)
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
	var encMap pb.PaillierEncOutputs
	json.Unmarshal([]byte(encArgs), &encMap)
	ciphertext1 = encMap.Ciphertext
	log.Printf("paillierEnc args: %s\n", encArgs)
	log.Printf("ciphertext1: %s\n", ciphertext1)


	encArgs2, err := wasmContract.EncryptPaillierArgs(plainArgs2)
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
	json.Unmarshal([]byte(encArgs2), &encMap)
	ciphertext2 = encMap.Ciphertext
	log.Printf("paillierEnc args: %s\n", encArgs2)
	log.Printf("ciphertext2: %s\n", ciphertext2)

	log.Printf("...... paillierEnc finished ......\n\n")
	return
}

/*
	----------------------------------------------------------
     dataid | owner | pubkey     | content  | user  | commitment
    ----------------------------------------------------------
        1   | owner | pubkeyOwn  | cipher1  | owner |			// store cipher1
    ----------------------------------------------------------
        2   | owner | pubkeyOwn  | cipher2  | owner |			// store cipher2
    ----------------------------------------------------------
        1   | owner | pubkeyOwn  | cipher1  | user  | commitment1       // authorize cipher1 to user
    ----------------------------------------------------------
        2   | owner | pubkeyOwn  | cipher2  | user  | commitment2       // authorize cipher2 to user
    ----------------------------------------------------------
        3   | owner | pubkeyOwn  | cipher3  | user  | 			// usr computes data1+data2
    ----------------------------------------------------------
        4   | owner | pubkeyOwn  | cipher4  | user  |			// user computes scalar*data1
    ----------------------------------------------------------
*/

func testInvokeWasmContract() {
	log.Printf("start testInvokeWasmContract.....\n")
	acc, err := usingAccount()
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
	}
	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

///////////////////////////////////////////////////////////////////////

	// test store
	log.Println("......start store......")
	// store cipher1
	args := map[string]string{
		"dataid": data1,
		"content": ciphertext1,
		"pubkey": paillierPubkey,
	}
	methodName := "store"
	txid, err := wasmContract.InvokeWasmContract(methodName, args)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	// store cipher2
	args2 := map[string]string{
		"dataid": data2,
		"content": ciphertext2,
		"pubkey": paillierPubkey,
	}
	txid, err = wasmContract.InvokeWasmContract(methodName, args2)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("......store finished......\n\n")


///////////////////////////////////////////////////////////////////////

	// test authorize
	log.Println("...... start authorize......")
	// get commitment for user
	commitment, err := wasmContract.GetPaillierAuth(ciphertext1, user)
	if err != nil {
		log.Printf("get paillier commitment err: %v", err)
		os.Exit(-1)
	}
	// authorize cipher1
	authArgs := map[string]string{
		"dataid": data1,
		"user": user,
		"commitment": commitment,
	}
	methodName = "authorize"
	txid, err = wasmContract.InvokeWasmContract(methodName, authArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("......authorize finished......\n\n")

	// authorize cipher2
	commitment, err = wasmContract.GetPaillierAuth(ciphertext2, user)
	if err != nil {
		log.Printf("get paillier commitment err: %v", err)
		os.Exit(-1)
	}
	authArgs2 := map[string]string{
		"dataid": data2,
		"user": user,
		"commitment": commitment,
	}
	txid, err = wasmContract.InvokeWasmContract(methodName, authArgs2)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("......authorize finished......\n\n")

///////////////////////////////////////////////////////////////////////
	testPaillierOps()
///////////////////////////////////////////////////////////////////////

	// test modify
	log.Println("......start modify......")
	modifyArgs := map[string]string{
		"dataid": data2,
		"content": "new data",
		"pubkey": paillierPubkey,
	}
	methodName = "modify"
	txid, err = wasmContract.InvokeWasmContract(methodName, modifyArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid

	// try get new data
	getArgs := map[string]string{
		"dataid": data2,
	}
	methodName = "get"
	response, err := wasmContract.QueryWasmContract(methodName, getArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("get new data: %s\n\n", string(response.GetResponse().GetResponse()[0]))
	log.Printf("...... modify finished......\n")

///////////////////////////////////////////////////////////////////////

	// test del
	log.Println("...... start del......")
	delArgs := map[string]string{
		"dataid": data2,
	}
	methodName = "del"
	txid, err = wasmContract.InvokeWasmContract(methodName, delArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid

	// try get deleted data
	getArgs = map[string]string{
		"dataid": data2,
	}
	methodName = "get"
	response, err = wasmContract.QueryWasmContract(methodName, getArgs)
	if err == nil {
		log.Printf("delete data failed for %s\n", getArgs["dataid"])
	} else {
		log.Printf("delete data success\n")
	}
	log.Printf("...... del finished......\n")

	log.Printf("finish testInvokeWasmContract......\n\n")
	return
}

// homomorphic operations
func testPaillierOps() {
	log.Printf("...... start homomorphic addition .....\n")
	acc, err := account.GetAccountFromFile("./newkeys/", "123")
	if err != nil {
		log.Printf("using account %s failed, err: %v", user, err)
		os.Exit(-1)
	}
	fmt.Printf("account: %v\n", acc)
	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, userAcc)

	// cipher3 = cipher1 + cipher2
	authArgs := map[string]string{
		"data1": data1,
		"data2": data2,
		"newid": dataAdd,
	}
	methodName := "add"
	txid, err := wasmContract.InvokeWasmContract(methodName, authArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("...... homomorphic addition finished ......\n\n")

	log.Printf("...... start homomorphic scalar mul .....\n")
	// cipher4 = cipher3 * cipher2
	authArgs2 := map[string]string{
		"dataid": data1,
		"scalar": scalar,
		"newid": dataMul,
	}
	methodName = "mul"
	txid, err = wasmContract.InvokeWasmContract(methodName, authArgs2)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid

	log.Printf("...... homomorphic scalar mul finished ......\n\n")
	return
}

// query ciphertexts
func testQuery() {
	log.Printf("...... start query .....\n")
	acc, err := account.GetAccountFromFile("./newkeys/", "123")
	if err != nil {
		log.Printf("using account %s failed, err: %v", user, err)
		os.Exit(-1)
	}
	fmt.Printf("account: %v\n", acc)

	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

	// query addition cipher
	args := map[string]string{
		"dataid": dataAdd,
	}
	methodName := "get"
	// query contract
	preExeRPCRes, err := wasmContract.QueryWasmContract(methodName, args)
	if err != nil {
		log.Printf("query error: %v", err)
		os.Exit(-1)
	}
	for _, res := range preExeRPCRes.GetResponse().GetResponse() {
		cipherAdd = string(res)
	}
	log.Printf("cipherAdd:%s\n", cipherAdd)

	// query scalar mul cipher
	args2 := map[string]string{
		"dataid": dataMul,
	}
	// query contract
	preExeRPCRes, err = wasmContract.QueryWasmContract(methodName, args2)
	if err != nil {
		log.Printf("query error: %v", err)
		os.Exit(-1)
	}
	for _, res := range preExeRPCRes.GetResponse().GetResponse() {
		cipherMul = string(res)
	}
	log.Printf("cipherMul:%s\n", cipherMul)

	log.Printf("...... query  finished ......\n\n")
	return
}

// decrypt cipherMul and cipherExp
func testDec() {
	log.Printf("start paillierDec......\n")
	acc, err := usingAccount()
	if err != nil {
		fmt.Printf("retrieveAccount err: %v\n", err)
		panic(err)
	}
	fmt.Printf("account: %v\n", acc)

	cipherArgs := map[string]string{
		"ciphertext": cipherAdd,
		"publicKey": paillierPubkey,
		"prvkeyPath": paillierPrvPath+paillierPrvFile,
		"password": password,
	}
	cipherArgs2 := map[string]string{
		"ciphertext": cipherMul,
		"publicKey": paillierPubkey,
		"prvkeyPath": paillierPrvPath+paillierPrvFile,
		"password": password,
	}
	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, contractAcc)

	decArgs, err := wasmContract.DecryptPaillierArgs(cipherArgs)
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
	var decMap pb.PaillierDecOutputs
	json.Unmarshal([]byte(decArgs), &decMap)
	plain1 := decMap.Plaintext
	log.Printf("decrypted data1+data2: %s\n", plain1)
	if plain1 != addition {
		fmt.Errorf("paillier addition result is not correct!\n")
	}

	decArgs2, err := wasmContract.DecryptPaillierArgs(cipherArgs2)
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
	json.Unmarshal([]byte(decArgs2), &decMap)
	plain2 := decMap.Plaintext
	log.Printf("decrypted data1*scalar: %s\n", plain2)
	if plain2 != scalarMul {
		fmt.Errorf("paillier scalar multiplication result is not correct!\n")
	}

	log.Printf("...... paillierDec finished ......\n\n")
	return
}

func main() {
	contractName = contractName + fmt.Sprintf("%d", time.Now().Unix()%1000000)
	println("contractname: ", contractName)

	testAccount()
	testDeployWasmContract()
	testKeyGen()
	testEnc()
	testInvokeWasmContract()
	testQuery()
	testDec()
}
