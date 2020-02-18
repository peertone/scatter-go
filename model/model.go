// model
package model

import (
	eos "github.com/eoscanada/eos-go"
)

type Request struct {
	Data   Data   `json:"data"`
	Plugin string `json:"plugin,omitempty"`
}

type Data struct {
	Type        string   `json:"type,omitempty"`
	Payload     *Payload `json:"payload,omitempty"`
	Appkey      string   `json:"appkey,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	Passthrough bool     `json:"passthrough"`
	ID          string   `json:"id,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`
	NextNonce   string   `json:"nextNonce,omitempty"`
}

type Payload struct {
	//Transaction    *Transaction    `json:"transaction,omitempty"`
	Transaction    *eos.Transaction `json:"transaction,omitempty"`
	Buf            *Buf             `json:"buf,omitempty"`
	Blockchain     string           `json:"blockchain,omitempty"`
	Network        *Network         `json:"network,omitempty"`
	RequiredFields *RequiredFields  `json:"requiredFields,omitempty"`
	Fields         *Fields          `json:"fields,omitempty"`
	Origin         string           `json:"origin,omitempty"`
}

type Fields struct {
	Accounts []Account `json:"accounts"`
}

type Account struct {
	Name       string      `json:"name"`
	Protocol   string      `json:"protocol,omitempty"`
	Host       string      `json:"host,omitempty"`
	Port       string      `json:"port,omitempty"`
	Blockchain string      `json:"blockchain,omitempty"`
	ChainID    string      `json:"chainId,omitempty"`
	Token      interface{} `json:"token,omitempty"`
	Authority  string      `json:"authority,omitempty"`
	PublicKey  string      `json:"publicKey,omitempty"`
	IsHardware bool        `json:"isHardware,omitempty"`
}

type Buf struct {
	Type string `json:"type,omitempty"`
	Data []int  `json:"data"`
}

type Network struct {
	Name       string      `json:"name,omitempty"`
	Protocol   string      `json:"protocol,omitempty"`
	Host       string      `json:"host,omitempty"`
	Port       string      `json:"port,omitempty"`
	Blockchain string      `json:"blockchain,omitempty"`
	ChainID    string      `json:"chainId,omitempty"`
	Token      interface{} `json:"token"`
}

type RequiredFields struct {
}

type Transaction struct {
	Expiration            string        `json:"expiration,omitempty"`
	RefBlockNum           int           `json:"ref_block_num,omitempty"`
	RefBlockPrefix        int64         `json:"ref_block_prefix,omitempty"`
	MaxNetUsageWords      int           `json:"max_net_usage_words,omitempty"`
	MaxCPUUsageMs         int           `json:"max_cpu_usage_ms,omitempty"`
	DelaySec              int           `json:"delay_sec,omitempty"`
	ContextFreeActions    []interface{} `json:"context_free_actions"`
	Actions               []Action      `json:"actions"`
	TransactionExtensions []interface{} `json:"transaction_extensions"`
}

type Action struct {
	Account       string          `json:"account,omitempty"`
	Name          string          `json:"name,omitempty"`
	Authorization []Authorization `json:"authorization,omitempty"`
	Data          string          `json:"data,omitempty"`
}

type Authorization struct {
	Actor      string `json:"actor,omitempty"`
	Permission string `json:"permission,omitempty"`
}

type Response struct {
	ID     string      `json:"id,omitempty"`
	Result interface{} `json:"result,omitempty"`
}

type Result struct {
	Hash           string         `json:"hash,omitempty"`
	PublicKey      string         `json:"publicKey,omitempty"`
	Name           string         `json:"name,omitempty"`
	Accounts       []Account      `json:"accounts,omitempty"`
	Signatures     []string       `json:"signatures,omitempty"`
	ReturnedFields ReturnedFields `json:"returnedFields"`
	Type           string         `json:"type,omitempty"`
	Message        string         `json:"message,omitempty"`
	Code           int            `json:"code,omitempty"`
	IsError        bool           `json:"isError,omitempty"`
}

type ReturnedFields struct {
}

type ResponseInfo struct {
	Success   bool
	Account   Account
	Type      string
	Rekey     bool
	Signature string
}
