package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xuperchain/xuper-sdk-go/account"
	"github.com/xuperchain/xuper-sdk-go/contract"
)

var (
	language = 1
	contractAcc = "XC1111111111111122@xuper"
	// generate user's account and save private.key to ./newkeys
	user        = "ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy"
	// create an account controlled by user
	userAcc     = "XC1111111111111111@xuper"
	transactionId = ""
)

// define blockchain node and blockchain name
var (
	contractName = "data_auth"
	node         = "localhost:37101"
	bcname       = "xuper"
	codePath 	 = "example/contract_code/data_auth.wasm"
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

/*
	----------------------------------------------------------
     dataid | owner | content  | expire  | user  | commitment
    ----------------------------------------------------------
        1   | owner | cipher1  | expire1 | owner |				 // store cipher1
    ----------------------------------------------------------
        2   | owner | cipher2  | expire2 | owner |				 // store cipher2
    ----------------------------------------------------------
        1   | owner | cipher1  | expire1 | user  | commitment1   // authorize cipher1 to user
    ----------------------------------------------------------
        2   | owner | cipher2  | expire2 | user  | commitment2   // authorize cipher2 to user
    ----------------------------------------------------------
        3   | user  | c3=c1+c2 | expire  | user  | 				 // usr computes cipher1+cipher2
    ----------------------------------------------------------
        4   | user  | c4=c3*c2 | expire  | user  |				 // user computes cipher3*cipher2
    ----------------------------------------------------------
        11  | user  | cipher1` | expire1 | user  |				 // owner shares cipher1 to user
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

	// test encrypt data
	log.Println("......start encrypt......")
	plainArgs := map[string]string{
		"cipher1": "25",
		"cipher2": "12",
	}
	encArgs, err := wasmContract.EncryptWasmArgs(plainArgs)
	if err != nil {
		log.Printf("Encrypt args failed, err: %v", err)
		os.Exit(-1)
	}
	cipher1 := encArgs["cipher1"]
	cipher2 := encArgs["cipher2"]
	log.Printf("encrypted args: %s\n", encArgs)
	log.Printf("...... encrypt finished ......\n\n")

///////////////////////////////////////////////////////////////////////

	// test store
	log.Println("......start store......")
	// store cipher1
	args := map[string]string{
		"dataid": "1",
		"content": cipher1,
		"expire": "20201010",
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
		"dataid": "2",
		"content": cipher2,
		"expire": "20201020",
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

	// test get
	log.Println("...... start get......")
	getArgs := map[string]string{
		"dataid": "1",
	}
	methodName = "get"
	response, err := wasmContract.QueryWasmContract(methodName, getArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("get data: %s", string(response.GetResponse().GetResponse()[0]))
	log.Printf("....... get finished......\n")

	// use user's address to query data, suppose to be error
	_, err = tryQuery(getArgs["dataid"])
	if ( err == nil ) {
		log.Printf("not supposed to query %s\n", args["dataid"])
	}

///////////////////////////////////////////////////////////////////////

	// test authorize
	log.Println("...... start authorize......")
	// get public key and signature
	pubkey := contract.GetPubkeyHexFromJson(wasmContract.Account.PublicKey)
	signature, err := wasmContract.SignAuthReq(cipher1, user, "commitment")
	if (err != nil) {
		log.Printf("sign authorize request failed, err: %v", err)
		os.Exit(-1)
	}
	// authorize cipher1
	authArgs := map[string]string{
		"dataid": "1",
		"user": user,
		"pubkey": pubkey,
		"signature": signature,
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
	log.Println("...... start authorize......")
	// get public key and signature
	signature, err = wasmContract.SignAuthReq(cipher2, user, "commitment")
	if (err != nil) {
		log.Printf("sign authorize request failed, err: %v", err)
		os.Exit(-1)
	}
	authArgs2 := map[string]string{
		"dataid": "2",
		"user": user,
		"pubkey": pubkey,
		"signature": signature,
	}
	methodName = "authorize"
	txid, err = wasmContract.InvokeWasmContract(methodName, authArgs2)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("......authorize finished......\n\n")

	// use user's address to query data. supposed to return cipher data
	content, err := tryQuery(authArgs["dataid"])
	if ( err != nil ) {
		log.Printf("query data falied for %s \n\n", args["dataid"])
	} else {
		log.Printf("data1: %s\n\n", content)
	}
	content, err = tryQuery(authArgs2["dataid"])
	if ( err != nil ) {
		log.Printf("query data falied for %s \n\n", args["dataid"])
	} else {
		log.Printf("data2: %s\n\n", content)
	}


///////////////////////////////////////////////////////////////////////
	testBinaryOps()
///////////////////////////////////////////////////////////////////////

	// test share
	log.Println("...... start share......")
	// get public key and signature
	signature, err = wasmContract.SignAuthReq(cipher1, user, "ownership")
	if (err != nil) {
		log.Printf("sign authorize request failed, err: %v", err)
		os.Exit(-1)
	}
	shareArgs := map[string]string{
		"dataid": "1",
		"toaddr": user,
		"newid": "11",
		"pubkey": pubkey,
		"signature": signature,
	}
	methodName = "share"
	txid, err = wasmContract.InvokeWasmContract(methodName, shareArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	log.Printf("...... share finished......\n\n")

	// query user's own  data, supposed to be same with the original one
	debug := tryDecrypt(shareArgs["newid"], "25")
	if ( debug == false ) {
		log.Printf("new decrypted is not equal to original data \n\n")
	} else {
		log.Printf("share test passed!!!\n\n")
	}

///////////////////////////////////////////////////////////////////////

	// test modify
	log.Println("......start modify......")
	modifyArgs := map[string]string{
		"dataid": "2",
		"content": "2222222",
		"expire": "20201030",
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
	getArgs = map[string]string{
		"dataid": "2",
	}
	methodName = "get"
	response, err = wasmContract.QueryWasmContract(methodName, getArgs)
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
		"dataid": "2",
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
		"dataid": "2",
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

// try add user's authorized data
func testBinaryOps() {
	log.Printf("...... start binaryops .....\n")
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
		"data1": "1",
		"data2": "2",
		"newid": "3",
	}
	methodName := "add"
	txid, err := wasmContract.InvokeWasmContract(methodName, authArgs)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	// cipher3 supposed to be 23+12=37
	if (!tryDecrypt("3", "37")) {
		log.Printf("addition error\n")
	} else {
		log.Printf("addition test passed!!!\n")
	}

	// cipher4 = cipher3 * cipher2
	authArgs2 := map[string]string{
		"data1": "3",
		"data2": "2",
		"newid": "4",
	}
	methodName = "mul"
	txid, err = wasmContract.InvokeWasmContract(methodName, authArgs2)
	if err != nil {
		log.Printf("InvokeWasmContract PostWasmContract failed, err: %v", err)
		os.Exit(-1)
	}
	log.Printf("txid: %v", txid)
	transactionId = txid
	// cipher3 supposed to be 37*12=444
	if (!tryDecrypt("4", "444")) {
		log.Printf("multiplication error\n")
	} else {
		log.Printf("multiplication test passed!!!\n")
	}
	log.Printf("...... binaryops finished ......\n\n")
	return
}

// query data using authorized address
func tryQuery(dataid string) (content string, err error){
	acc, err := account.GetAccountFromFile("./newkeys/", "123")
	if err != nil {
		log.Printf("using account %s failed, err: %v", user, err)
		os.Exit(-1)
	}
	fmt.Printf("account: %v\n", acc)

	// initialize a client to operate the contract
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, userAcc)

	// set query function method and args
	args := map[string]string{
		"dataid": dataid,
	}
	methodName := "get"

	// query contract
	preExeRPCRes, err := wasmContract.QueryWasmContract(methodName, args)
	if err != nil {
		return "", err
	}

	for _, res := range preExeRPCRes.GetResponse().GetResponse() {
		content = string(res)
	}
	return
}

// decrypt shared data, plaintext is supposed to be content
func tryDecrypt(newid, content string) bool{
	cipher, err := tryQuery(newid)
	if err != nil {
		log.Printf("failed to query data %s, err: %v", newid, err)
		os.Exit(-1)
	}
	acc, err := account.GetAccountFromFile("./newkeys/", "123")
	if err != nil {
		log.Printf("using account %s failed, err: %v", user, err)
		os.Exit(-1)
	}
	wasmContract := contract.InitWasmContract(acc, node, bcname, contractName, userAcc)

	// call tee to decrypt data
	args := map[string]string{
		"key": cipher,
	}
	plainMap64, err := wasmContract.DecryptArgs(0, args)
	err = json.Unmarshal([]byte(plainMap64), &args)
	plainData64 := args["key"]
	// data is in base64 format, decoding required
	myplain, err := base64.StdEncoding.DecodeString(plainData64)
	return string(myplain)==content
}

func main() {
	contractName = contractName + fmt.Sprintf("%d", time.Now().Unix()%1000000)
	println("contractname: ", contractName)

	testAccount()
	testDeployWasmContract()
	testInvokeWasmContract()
}
