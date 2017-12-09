package key

import (
	"encoding/json"
	"fmt"
	"github.com/open-horizon/anax/cli/cliutils"
	"github.com/open-horizon/rsapss-tool/listkeys"
	"os"
	"os/user"
	"path"
	"strings"
	"text/template"
)

var developerKeysPath string
var anaxTrustedKeysPath string

const (
	trustKeysTemplate = `
{{separator 80}}
x509 Certificate Serial Number                               Have Priv?  Trust?
(SubjectNames)
{{separator 80}}
{{range $f, $c := .}}
{{ $c.Pair.SerialOctet }}  {{$c.Pair.HavePrivateKey}}        {{$c.Trusted}}
{{range $k, $v := $c.Pair.SimpleSubjectNames}}{{$k}}:{{$v}}
{{end}}{{end}}
`
)

type trustPair struct {
	Pair    listkeys.KeyPair
	Trusted bool
}

func init() {
	// TODO: set up these paths with user input and defaults

	// using this method instead of the cgo-dependent user home dir method
	currUser, err := user.Current()
	if err != nil {
		cliutils.Fatal(cliutils.INTERNAL_ERROR, "Unable to determine current user.")
	}

	developerKeysPath = path.Join(currUser.HomeDir, ".rsapsstool", "keypairs")
	anaxTrustedKeysPath = "/var/horizon/userkeys"
}

// TODO: should this output be enriched with the x509 cert reading stuff in rsapss-tool?
func ListFromAnaxAPI() {
	apiOutput := make(map[string][]string, 0)
	// Note: it is allowed to get /publickey before post /node is called, so we don't have to check for that error
	cliutils.HorizonGet("publickey", []int{200}, &apiOutput)
	var ok bool
	if _, ok = apiOutput["pem"]; !ok {
		cliutils.Fatal(cliutils.HTTP_ERROR, "horizon api publickey output did not include 'pem' key")
	}
	jsonBytes, err := json.MarshalIndent(apiOutput["pem"], "", cliutils.JSON_INDENT)
	if err != nil {
		cliutils.Fatal(cliutils.JSON_PARSING_ERROR, "failed to marshal 'key list' output: %v", err)
	}
	fmt.Printf("%s\n", jsonBytes)
}

func readKeys(dir string) (map[string]listkeys.KeyPair, error) {
	// important that we always return empty data structure even in error conditions

	keyList := make(map[string]listkeys.KeyPair)

	var err error
	if _, err = os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			cliutils.Warn(fmt.Sprintf("Keys directory %v does not exist\n", dir))
		}
	} else {

		keyList, err = listkeys.ListPairs(dir)
		if err != nil {
			return keyList, fmt.Errorf("Error reading keys from %v. Error: %v", dir, err)
		}
	}

	return keyList, nil
}

// TODO: find some reasonable way to order these that people like, for now it's all the ones you probably manage at top and the others below
// N.B. This is destructive of the trustedKeys map
func trustList(devKeys, trustedKeys map[string]listkeys.KeyPair) []trustPair {
	isTrusted := func(serial string) bool {
		for tSerial, _ := range trustedKeys {
			if serial == tSerial {
				// remove the recorded trusted key from the map so we can avoid unnecessary iteration later
				delete(trustedKeys, serial)
				return true
			}
		}
		return false
	}

	var trusted []trustPair

	for serial, keyPair := range devKeys {
		trusted = append(trusted, trustPair{Pair: keyPair, Trusted: isTrusted(serial)})
	}

	// now add the remaining trusted ones to the list if they aren't there already
	for _, keyPair := range trustedKeys {
		trusted = append(trusted, trustPair{Pair: keyPair, Trusted: true})
	}

	return trusted
}

func List() {
	developerKeys, err := readKeys(developerKeysPath)
	if err != nil {
		cliutils.Error(err.Error())
	}

	// Until Anax APIs work with x509 keys we will work with files on-disk

	// N.B. we're gonna mutate this map
	tempAnaxTrustedKeys, err := readKeys(anaxTrustedKeysPath)
	if err != nil {
		cliutils.Error(err.Error())
	}

	t := template.Must(template.New("trustlist").Funcs(map[string]interface{}{"separator": func(ct int) string {
		return strings.Repeat("-", ct)
	}}).Parse(trustKeysTemplate))
	if err := t.Execute(os.Stdout, trustList(developerKeys, tempAnaxTrustedKeys)); err != nil {
		cliutils.Error(err.Error())
	}
}

// TODO: add a function to trust a cert, this takes a serial number and copies that x509 cert to anaxTrustedKeysPath from developerKeysPath

// TODO: add a function to generate a cert, delegate directly to rsapss-tool generatekeys

// TODO: add a function that signs with a private key, delegate directly to rsapss-tool sign
