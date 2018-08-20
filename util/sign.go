package util

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"

	"github.com/spf13/viper"

	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"
)

type signInput struct {
	InputHex   string `json:"inputHex"`
	PubHashHex string `json:"pubHashHex"`
	TimeStamp  int64  `json:"timestamp"`
	ServiceID  string `json:"serviceId"`
}

type generateInput struct {
	Count     int    `json:"count"`
	ServiceID string `json:"serviceId"`
	TimeStamp int64  `json:"timestamp"`
}

//SignData 签数结果
type SignData struct {
	R               string `json:"r"`
	S               string `json:"s"`
	SignatureDerHex string `json:"signatureDerHex"`
}

//SignResponse 秘钥服务签名返回结构
type SignResponse struct {
	Code int       `json:"code"`
	Data *SignData `json:"data"`
	Msg  string    `json:"msg"`
}

//PubkeyData 秘钥服务公钥结果
type PubkeyData struct {
	PubHashHex string `json:"pubHashHex"`
	PubHex     string `json:"pubHex"`
}

//GenerateData 秘钥服务生成公钥接口数据
type GenerateData struct {
	Keys []*PubkeyData `json:"keys"`
}

//GenerateResponse 秘钥服务生成公钥接口返回结构
type GenerateResponse struct {
	Code int `json:"code"`
	Data *GenerateData
	Msg  string `json:"msg"`
}

func init() {
	viper.SetDefault("KEYSTORE.url", "http://localhost:9999")
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func calAPI(api string, data []byte) ([]byte, error) {
	client := &http.Client{}
	keyStorePK := viper.GetString("KEYSTORE.keystore_private_key")

	keypkByte, err := hex.DecodeString(keyStorePK)
	if err != nil {
		log.Error("postData failed", "err", err.Error())
		return nil, err
	}

	keyPk, _ := btcec.PrivKeyFromBytes(btcec.S256(), keypkByte)

	postDataHash := calcHash(data, sha256.New())

	postSign, err := keyPk.Sign(postDataHash)
	if err != nil {
		log.Error("postData failed", "err", err.Error())
		return nil, err
	}

	url := strings.Join([]string{viper.GetString("KEYSTORE.url"), api}, "/")

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Error("postData failed", "err", err.Error())
		return nil, err
	}

	req.Close = true

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("signature", hex.EncodeToString(postSign.Serialize()))
	req.Header.Set("serviceId", viper.GetString("KEYSTORE.service_id"))
	resp, err := client.Do(req)

	if err != nil {
		log.Error("postData failed", "err", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)

}

//Generate 生成公钥
func Generate(count int) (*GenerateData, error) {
	inputData := generateInput{
		Count:     count,
		ServiceID: viper.GetString("KEYSTORE.service_id"),
		TimeStamp: time.Now().Unix(),
	}

	postData, err := json.Marshal(&inputData)
	if err != nil {
		log.Error("signData failed", "err", err.Error())
		return nil, err
	}

	body, err := calAPI("key/generate", postData)
	if err != nil {
		log.Error("generate failed", "err", err.Error())
		return nil, err
	}

	var res GenerateResponse
	err1 := json.Unmarshal(body, &res)
	if err1 != nil {
		log.Error("generate failed", "err", err.Error())
		return nil, err
	}

	if res.Code == 0 {
		return res.Data, nil
	}

	return nil, errors.Errorf("generate result code is %d", res.Code)

}

//Sign 使用签名服务对待签名数据进行签名
func Sign(input string, pubkeyHash string) (*SignData, error) {
	inputData := signInput{
		InputHex:   input,
		PubHashHex: pubkeyHash,
		TimeStamp:  time.Now().Unix(),
		ServiceID:  viper.GetString("KEYSTORE.service_id"),
	}

	postData, err := json.Marshal(&inputData)
	if err != nil {
		log.Error("signData failed", "err", err.Error())
		return nil, err
	}

	body, err := calAPI("key/sign", postData)
	if err != nil {
		log.Error("signData failed", "err", err.Error())
		return nil, err
	}

	var sigRes SignResponse
	err1 := json.Unmarshal(body, &sigRes)
	if err1 != nil {
		log.Error("signData failed", "err", err.Error())
		return nil, err
	}

	if sigRes.Code == 0 {
		return sigRes.Data, nil
	}

	return nil, errors.Errorf("sign result code is %d", sigRes.Code)
}
