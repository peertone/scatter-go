// services_test
package scattergo

import (
	"fmt"
	"testing"

	eosapi "./eosapi"
	mod "./model"
	eos "github.com/eoscanada/eos-go"
	"github.com/stretchr/testify/assert"
)

func T_estConnect(t *testing.T) {
	scatter := Scatter{
		Plugin: "testapp",
		Origin: "testapp",
	}
	connected := scatter.Connect()
	assert.Equal(t, true, connected)

}

func T_estGetIdentity(t *testing.T) {
	scatter := Scatter{
		Plugin: "testapp",
		Origin: "testapp",
		Network: &mod.Network{
			Name:       "",
			Protocol:   "https",
			Host:       "api.jungle.alohaeos.com",
			Port:       "443",
			Blockchain: "eos",
			ChainID:    "e70aaab8997e1dfce58fbfac80cbbb8fecec7b99cf982a9444273cbc64c41473", //jungle testnet
		},
	}
	account, err := scatter.GetIdentity()
	assert.Nil(t, err)
	fmt.Println("Account details ", account)
}

func TestGetSignature(t *testing.T) {
	scatter := Scatter{
		Plugin: "testapp1",
		Origin: "testapp1",
		Network: &mod.Network{
			Name:       "",
			Protocol:   "https",
			Host:       "api.jungle.alohaeos.com",
			Port:       "443",
			Blockchain: "eos",
			ChainID:    "e70aaab8997e1dfce58fbfac80cbbb8fecec7b99cf982a9444273cbc64c41473", //jungle testnet
		},
	}
	account, err := scatter.GetIdentity()
	if err != nil {
		t.Fatalf("%s", err)
	}
	tx := getTranasaction(account.Name, account.Authority)
	//compose requests
	payload := mod.Payload{
		Network:     scatter.Network,
		Blockchain:  "eos",
		Transaction: tx,
		Origin:      scatter.Origin,
	}
	scatter.Payload = &payload
	signature, err := scatter.GetSignature()
	assert.Nil(t, err)
	fmt.Println("Valid Signature : ", signature)
}

func getTranasaction(actor string, permission string) *eos.Transaction {
	//actual transaction for smart contract should be created
	/*txOpts := &eos.TxOptions{}
	txn := eos.NewTransaction([]*eos.Action{}, txOpts) */
	fileDetails := eosapi.UserDetails{UserName: eos.AccountName("testinguser1"), UserStruct: eosapi.User{UserName: eos.AccountName("testinguser1"), PublicKey: "---EOS6Mdf8Ry2SAFrpp6kXkQD4JtGe4h933hW4C96LV6PhQLrAXLKLv---", Activated: false}}
	api := eos.New("https://api.jungle.alohaeos.com:443")
	txOpts := &eos.TxOptions{}
	if err := txOpts.FillFromChain(api); err != nil {
		panic(fmt.Errorf("filling tx opts: %s", err))
	}
	txn := eos.NewTransaction([]*eos.Action{{Account: eos.AccountName("testinguser1"), Name: eos.ActionName("adduser"), Authorization: []eos.PermissionLevel{
		{eos.AccountName(actor), eos.PermissionName(permission)},
	}, ActionData: eos.NewActionData(fileDetails)}}, txOpts)
	return txn
}

func T_estForgetIdentity(t *testing.T) {
	scatter := Scatter{
		Plugin: "testapp",
		Origin: "testapp",
	}
	result := scatter.ForgetIdentity()
	assert.Equal(t, true, result)
}
