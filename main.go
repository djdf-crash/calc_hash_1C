package main

import (
	"C"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/sys/windows/registry"
	"hash"
	"log"
	_ "runtime/cgo"
)

const (
	RegProgID = "AddIn.ComHashCalculate"
	RegCLSID  = "{C79018B1-C93F-4BAA-8262-3E10D4299584}"
	RegDesc   = "COM Wrapper for calc hash"
)

//export GetVersion
func GetVersion() string {
	return "v0.0.1"
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

//export DllGetClassObject
func DllGetClassObject() {
}

//export DllRegisterServer
func DllRegisterServer() int {

	return registerKeys()
}

func registerKeys() int {
	newKey, _, err := registry.CreateKey(registry.CLASSES_ROOT, `AppID\`+RegCLSID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegDesc)

	keyClassesRootCLSID := `CLSID\` + RegCLSID

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, keyClassesRootCLSID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegDesc)

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, keyClassesRootCLSID+`\InprocServer32`, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	//exPath, err := filepath.Abs(os.Args[1])
	//if err != nil {
	//	return 0
	//}
	exPath := `D:\GolangProjects\calc_hash_1C\CalcHash1C.dll`
	setStringValue(newKey, "", exPath)

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, keyClassesRootCLSID+`\ProgID`, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegProgID)

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, RegProgID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegDesc)

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, RegProgID+`\CLSID`, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegCLSID)

	newKey, _, err = registry.CreateKey(registry.CLASSES_ROOT, `WOW6432Node\AppID\`+RegCLSID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegProgID)

	newKey, _, err = registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\AppID\`+RegCLSID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegProgID)

	keySoftwareClassesCLSID := `SOFTWARE\Classes\CLSID\` + RegCLSID

	newKey, _, err = registry.CreateKey(registry.LOCAL_MACHINE, keySoftwareClassesCLSID, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", RegDesc)

	newKey, _, err = registry.CreateKey(registry.LOCAL_MACHINE, keySoftwareClassesCLSID+`\InprocServer32`, registry.SET_VALUE)
	if err != nil {
		return 0
	}
	setStringValue(newKey, "", exPath)

	newKey, _, err = registry.CreateKey(registry.LOCAL_MACHINE, keySoftwareClassesCLSID+`\ProgID`, registry.SET_VALUE)
	if err != nil {
		return 0
	}

	setStringValue(newKey, "", RegProgID)

	return 1
}

//export DllUnregisterServer
func DllUnregisterServer() {

}

func setStringValue(k registry.Key, name, value string) {

	err := k.SetStringValue(name, value)
	defer k.Close()

	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	//registerKeys()

}
