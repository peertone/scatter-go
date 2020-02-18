// scattergo
package scattergo

import (
	"encoding/json"
	"errors"
	"flag"
	//"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	mod "github.com/peertone/scattergo/model"
	util "github.com/peertone/scattergo/util"
)

const APPKEY_ID_LENGTH = 24

const (
	//Request types
	REQUEST_PAIR                         = "pair"
	REQUEST_API                          = "api"
	REQUEST_API_IDENTITY_FROM_PERMISSION = "identityFromPermissions"
	REQUEST_API_GET_IDENTITY             = "getOrRequestIdentity"
	REQUEST_API_SIGNATURE                = "requestSignature"
	RQUEST_API_FORGET_IDENTITY           = "forgetIdentity"
	REQUEST_REKEYED                      = "rekeyed"

	//Response types
	RESPONSE_PAIRED = "paired"
	RESPONSE_REKEY  = "rekey"
	RESPONSE_API    = "api"
)

var addr = flag.String("addr", "local.get-scatter.com:50006", "http service address")
var msgChan = make(chan string, 20)
var respChan = make(chan string)
var done = make(chan bool)

var connected string
var paired bool
var appKey string
var Nonce = "0"
var apiRequestId string

type Scatter struct {
	Plugin  string       `json:"plugin,omitempty"`
	Origin  string       `json:"origin,omitempty"`
	Network *mod.Network `json:"network,omitempty"`
	Account string       `json:"account,omitempty"`
	Name    string       `json:"name,omitempty"`
	Payload *mod.Payload `json:"payload,omitempty"`
	Data    string       `json:"data,omitempty"` //used for signature
}

func socketConnection() (*websocket.Conn, error) {
	u := url.URL{Scheme: "wss", Host: *addr, Path: "/socket.io/?EIO=3&transport=websocket"}
	var err error
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Println("dial:", err)
		return conn, err
	}
	return conn, nil
}

func CloseSocketConnection(conn *websocket.Conn) {
	conn.Close()
}

func receiveResponse(conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			return
		}
		log.Printf("recv: %s", message)
		msgChan <- string(message)
		//log.Println("--sent msg to chan--")
	}

}

func processResponse() (mod.ResponseInfo, error) {
	responseInfo := mod.ResponseInfo{}
	for {
		select {
		case retMsg := <-msgChan:
			if (strings.Index(retMsg, "42/scatter")) != -1 {
				retMsg = strings.Replace(retMsg, "42/scatter,", "", -1)
				index := strings.Index(retMsg, ",")
				if index != -1 {
					respType := retMsg[2 : index-1] //to get the first element from the response to determine the response type
					log.Println(retMsg[2 : index-1])
					data := retMsg[index+1 : len(retMsg)-1]
					switch respType {
					case RESPONSE_PAIRED:
						isPaired := handlePairedResponse(data)
						responseInfo.Success = isPaired
						responseInfo.Type = RESPONSE_PAIRED
						if isPaired {
							paired = true
						}
						return responseInfo, nil
					case RESPONSE_REKEY:
						rekey, err := handleRekeyResponse(data)
						//fmt.Println("Rekey : ", rekey)
						responseInfo.Type = RESPONSE_REKEY
						responseInfo.Rekey = rekey
						if err != nil {
							responseInfo.Success = false
						} else {
							responseInfo.Success = true
						}

						return responseInfo, err
					case RESPONSE_API:
						response, account, err := handleApiResponse(data)
						if err != nil {
							responseInfo.Success = false
						} else {
							responseInfo.Success = true
						}
						responseInfo.Type = RESPONSE_API
						responseInfo.Signature = response
						responseInfo.Account = account
						return responseInfo, err
					}
				}
			}
		}
	}
}

func handlePairedResponse(data string) bool {
	isPaired, err := strconv.ParseBool(data)
	if err != nil {
		return false
	}
	if isPaired {
		if appKey != "" {
			return true
		}
	}
	return false
}

func handleRekeyResponse(data string) (bool, error) {
	isRekey, err := strconv.ParseBool(data)
	if err != nil {
		return false, err
	}
	if !isRekey {
		return true, nil
	}
	return false, nil
}

func handleApiResponse(data string) (string, mod.Account, error) {
	//parse json and validate ID
	response := mod.Response{}
	err := json.Unmarshal([]byte(data), &response)
	if err != nil {
		log.Println("Response unmarshal error ", err)
		return "", mod.Account{}, err
	}

	if response.ID != apiRequestId {
		return "", mod.Account{}, errors.New("Invalid request ID in the response")
	}

	resultBool, ok := response.Result.(bool)
	if ok {
		if resultBool {
			return "", mod.Account{}, nil
		}
		return "", mod.Account{}, errors.New("ForgetIdentity request failed")
	}
	var result mod.Result
	resultObj, ok := response.Result.(map[string]interface{})
	if ok {
		jsonbody, _ := json.Marshal(resultObj)
		err = json.Unmarshal(jsonbody, &result)
		if err != nil {
			log.Println("Result struct unmarshal error ", err)
			return "", mod.Account{}, err
		}
	}

	if len(result.Signatures) > 0 {
		return result.Signatures[0], mod.Account{}, nil
	}
	/*if response.Result.Hash != "" && response.Result.IsError {
		return "", mod.Account{}, errors.New(response.Result.Message)
	} */
	if result.Code != 0 && result.IsError {
		return "", mod.Account{}, errors.New(result.Message)
	}
	return "", result.Accounts[0], nil

}

func sendMessage(reqType, subType string, scatter *Scatter, conn *websocket.Conn) error {
	reqMessage := ""
	switch reqType {
	case REQUEST_PAIR:
		appkey := ""
		passthrough := false
		if appkeyIsStored() {
			appkey = getStoredHashedAppkey()
			passthrough = true
		} else {
			appkey = util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH) //"appkey:" + util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
		}

		request := mod.Request{
			Plugin: scatter.Plugin,
			Data: mod.Data{
				Appkey:      appkey,
				Origin:      scatter.Origin,
				Passthrough: passthrough,
			},
		}

		jsonPayload, err := getJson(request)
		if err != nil {
			log.Println("Pair request : ", err)
			return err
		}
		reqMessage = `42/scatter,["pair",` + jsonPayload + `]`

	case REQUEST_API:
		request := mod.Request{}
		switch subType {
		case REQUEST_API_IDENTITY_FROM_PERMISSION:
			//should check if paring was successful
			//fmt.Println("--In GetIdentityFromPermission--")
			unHashedNextNonce := util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			hashedNextNonce, _ := util.GetSHA256Hash(unHashedNextNonce)
			request = mod.Request{
				Data: mod.Data{
					Type: REQUEST_API_IDENTITY_FROM_PERMISSION,
					Payload: &mod.Payload{
						Origin: scatter.Origin,
					},
					ID:        util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH),
					Appkey:    appKey,
					Nonce:     Nonce,
					NextNonce: unHashedNextNonce,
				},
				Plugin: scatter.Plugin,
			}
			Nonce = hashedNextNonce
		case REQUEST_API_GET_IDENTITY:
			accounts := make([]mod.Account, 0)
			account := mod.Account{
				Name:       scatter.Network.Name,
				Protocol:   scatter.Network.Protocol,
				Host:       scatter.Network.Host,
				Port:       scatter.Network.Port,
				Blockchain: scatter.Network.Blockchain,
				ChainID:    scatter.Network.ChainID,
			}
			apiRequestId = util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			accounts = append(accounts, account)
			unHashedNextNonce := util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			hashedNextNonce, _ := util.GetSHA256Hash(unHashedNextNonce)
			request = mod.Request{
				Data: mod.Data{
					Type: REQUEST_API_GET_IDENTITY,
					Payload: &mod.Payload{
						Fields: &mod.Fields{
							Accounts: accounts,
						},
						Origin: scatter.Origin,
					},
					ID:        apiRequestId,
					Appkey:    appKey,
					Nonce:     Nonce, // first request with getIdentity
					NextNonce: unHashedNextNonce,
				},
				Plugin: scatter.Plugin,
			}
			Nonce = hashedNextNonce

		case REQUEST_API_SIGNATURE:
			//yet to compose complete transaction object
			apiRequestId = util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			unHashedNextNonce := util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			hashedNextNonce, _ := util.GetSHA256Hash(unHashedNextNonce)
			request = mod.Request{
				Data: mod.Data{
					Type:      REQUEST_API_SIGNATURE,
					Payload:   scatter.Payload,
					ID:        apiRequestId,
					Appkey:    appKey,
					Nonce:     Nonce,
					NextNonce: unHashedNextNonce,
				},
				Plugin: scatter.Plugin,
			}
			Nonce = hashedNextNonce

		case RQUEST_API_FORGET_IDENTITY:
			apiRequestId = util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			unHashedNextNonce := util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
			hashedNextNonce, _ := util.GetSHA256Hash(unHashedNextNonce)
			request = mod.Request{
				Plugin: scatter.Plugin,
				Data: mod.Data{
					Type: RQUEST_API_FORGET_IDENTITY,
					Payload: &mod.Payload{
						Origin: scatter.Origin,
					},
					Appkey:    appKey,
					ID:        apiRequestId,
					Nonce:     "0",
					NextNonce: unHashedNextNonce,
				},
			}
			Nonce = hashedNextNonce
		}
		jsonPayload, err := getJson(request)
		if err != nil {
			log.Println("GetIdentity request Error : ", err)
			return err
		}
		reqMessage = `42/scatter,["api",` + jsonPayload + `]`

	case REQUEST_REKEYED:
		appKey = util.GetRandomAlphaNumbericValue(APPKEY_ID_LENGTH)
		request := mod.Request{
			Plugin: scatter.Plugin,
			Data: mod.Data{
				Appkey: "appkey:" + appKey,
				Origin: scatter.Origin,
			},
		}
		appKey, _ = util.GetSHA256Hash("appkey:" + appKey)
		jsonPayload, err := getJson(request)
		if err != nil {
			log.Println("Rekeyed request Error: ", err)
			return err
		}
		reqMessage = `42/scatter,["rekeyed",` + jsonPayload + `]`
	}
	log.Println("Request : ", reqMessage)
	err := conn.WriteMessage(websocket.TextMessage, []byte(reqMessage))
	if err != nil {
		log.Println("Failed to send message : ", reqType, " ", err)
		return err
	}
	return nil
}

func appkeyIsStored() bool {
	if appKey != "" {
		return true
	}
	return false

}

func getStoredHashedAppkey() string {
	return appKey
}

func getJson(object interface{}) (string, error) {
	jsonStr, err := json.Marshal(object)
	if err != nil {
		return "", errors.New("Marshal failed")
	}
	return string(jsonStr), nil
}

func (scatter *Scatter) Connect() bool {
	initializeVariables()
	conn, err := socketConnection()
	if err != nil {
		return false
	}
	defer CloseSocketConnection(conn)

	go receiveResponse(conn)
	if paired {
		log.Println("The app key is already paired")
		return true
	} else {
		err = sendMessage(REQUEST_PAIR, "", scatter, conn)
		if err != nil {
			log.Println("Failed to send message", err)
			return false
		}
	}
	response, err := processResponse()

	if err != nil {
		log.Println("Initial websocket handshake failed", err)
		return false
	}
	if response.Success && response.Type == RESPONSE_REKEY {
		if response.Rekey {
			err := sendMessage(REQUEST_REKEYED, "", scatter, conn)
			if err != nil {
				log.Println("Failed to send rekeyed message", err)
				return false
			}
			response, err = processResponse()
			if err != nil {
				log.Println("Pairing failed ", err)
				return false
			}
			if response.Success && response.Type == RESPONSE_PAIRED {
				return true
			}
			return false
		} else {
			log.Println("Error in connection : ", err)
			return false
		}
	}

	return false

}

func (scatter *Scatter) GetIdentity() (mod.Account, error) {
	if !paired {
		//log.Println("Pair the device again")
		//call Connect method
		connected := scatter.Connect()
		if !connected {
			return mod.Account{}, errors.New("getIdentity request failed")
		}
	}

	conn, err := socketConnection()
	if err != nil {
		return mod.Account{}, errors.New("Connection failed")
	}
	defer CloseSocketConnection(conn)

	account := mod.Account{}

	go receiveResponse(conn)

	err = sendMessage(REQUEST_API, REQUEST_API_GET_IDENTITY, scatter, conn)
	if err != nil {
		log.Println("Failed to send message", err)
		return account, err
	}
	response, err := processResponse()
	if err != nil {
		log.Println("getIdentity request failed : ", err)
		return mod.Account{}, err
	}
	if response.Success && response.Type == RESPONSE_API && response.Account.PublicKey != "" {
		return response.Account, nil
	}

	return mod.Account{}, errors.New("getIdentity request failed")
}

func (scatter *Scatter) GetIdentityFromPermissions() (mod.Account, error) {
	if !paired {
		//call Connect method
		connected := scatter.Connect()
		if !connected {
			return mod.Account{}, errors.New("getIdentity request failed")
		}
	}

	conn, err := socketConnection()
	if err != nil {
		return mod.Account{}, errors.New("Connection failed")
	}
	defer CloseSocketConnection(conn)

	account := mod.Account{}

	go receiveResponse(conn)

	err = sendMessage(REQUEST_API, REQUEST_API_IDENTITY_FROM_PERMISSION, scatter, conn)
	if err != nil {
		log.Println("Failed to send message", err)
		return account, err
	}
	response, err := processResponse()
	if err != nil {
		log.Println("getIdentityFromPermissions request failed : ", err)
		return mod.Account{}, err
	}
	if response.Success && response.Type == RESPONSE_API && response.Account.PublicKey != "" {
		return response.Account, nil
	}

	return mod.Account{}, errors.New("getIdentity request failed")
}

func (scatter *Scatter) GetSignature() (string, error) {
	if !paired {
		//call Connect method
		connected := scatter.Connect()
		if !connected {
			return "", errors.New("requestSignature request failed")
		}
	}

	conn, err := socketConnection()
	if err != nil {
		return "", errors.New("Connection failed")
	}
	defer CloseSocketConnection(conn)

	go receiveResponse(conn)

	//send get signature request
	err = sendMessage(REQUEST_API, REQUEST_API_SIGNATURE, scatter, conn)
	if err != nil {
		log.Println("Failed to send message getsignature request")

		return "", err
	}

	response, err := processResponse()
	if err != nil {
		return "", err
	}

	if response.Type == RESPONSE_API && response.Signature != "" {
		initializeVariables()
		return response.Signature, nil
	}

	return "", errors.New("requestSignature request failed")
}
func (scatter *Scatter) ForgetIdentity() bool {
	if !paired {
		//call Connect method
		connected := scatter.Connect()
		if !connected {
			return false
		}
	}

	conn, err := socketConnection()
	if err != nil {
		return false
	}
	defer CloseSocketConnection(conn)

	go receiveResponse(conn)

	//send forgetIdentity request
	err = sendMessage(REQUEST_API, RQUEST_API_FORGET_IDENTITY, scatter, conn)
	if err != nil {
		log.Println("Failed to send message forgetIdentity request")
		return false
	}

	response, err := processResponse()
	if err != nil {
		return false
	}
	initializeVariables()
	return response.Success

}

func (scatter *Scatter) ResetNonce() {
	Nonce = "0"
}

func initializeVariables() {
	paired = false
	appKey = ""
	Nonce = "0"
	apiRequestId = ""
}
