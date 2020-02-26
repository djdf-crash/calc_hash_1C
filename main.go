package main

import (
	//"C"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"hash"
	"log"
)

const (
	RegProgID = "1C83.ComHashCalculatePython"
	RegCLSID = "{C79018B1-C93F-4BAA-8262-3E10D4299584}"
	RegDesc = "COM Wrapper for calc hash"
)

//export CalculateHashFor1C
type CalculateHashFor1C struct {
	CalcHashFunc func() string
}

//export CalcHash
func CalcHash(hashTypeStr, data, secret string) string {

	var hashTypeFunc func() hash.Hash

	switch hashTypeStr {
	case "sha256":
		hashTypeFunc = sha256.New
	case "md5":
		hashTypeFunc = md5.New
	case "sha512":
		hashTypeFunc = sha512.New
	case "sha1":
		hashTypeFunc = sha1.New
	default:
		return ""
	}

	h := hmac.New(hashTypeFunc, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

//export DllInstall
func DllInstall() {

}

//export DllRegisterServer
func DllRegisterServer() int {

	return 1
}

//export DllUnregisterServer
func DllUnregisterServer() {

}

func main() {
	k, err := registry.OpenKey(registry.CLASSES_ROOT, `AddIn.vk_garant\Clsid`, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()

	s, _, err := k.GetStringValue("")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Windows system root is %q\n", s)


}