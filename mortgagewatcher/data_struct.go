package mortgagewatcher

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/txscript"
)

var prefix = []byte{0x00, 0x66, 0x67, 0x70}

//Message 抵押币Message信息
type Message struct {
	Address   string `json:"a"`
	ChainName string `json:"b"`
	APPNumber uint32 `json:"n"`
}

//CreatePayLoadScript 通过message结构生成op_return script
func CreatePayLoadScript(message *Message) ([]byte, error) {
	builder := txscript.NewScriptBuilder()

	builder.AddOp(txscript.OP_RETURN)
	//prefix "FGP"
	builder.AddData(prefix)

	//添加chainName
	builder.AddData([]byte(message.ChainName))

	//添加app number
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, message.APPNumber)
	if err != nil {
		return nil, err
	}
	builder.AddData(buf.Bytes())

	//添加Address
	builder.AddData([]byte(message.Address))

	return builder.Script()
}

//ParserPayLoadScript 解析op_return script到Message
func ParserPayLoadScript(script []byte) (*Message, error) {
	message := &Message{}

	payload, err := txscript.PushedData(script)
	if err != nil {
		return nil, err
	}

	if len(payload) != 4 {
		return nil, errors.New("payload len error")
	}

	if !bytes.Equal(payload[0], prefix) {
		return nil, errors.New("payload prefix error")
	}

	//parser chainName
	message.ChainName = string(payload[1])

	buf := bytes.NewBuffer(payload[2])
	err = binary.Read(buf, binary.BigEndian, &message.APPNumber)
	if err != nil {
		return nil, err
	}

	message.Address = string(payload[3])

	return message, nil
}

//AddressInfo 充币地址信息
type AddressInfo struct {
	Address string
	Amount  int64
}

//SubTransaction 铸币/熔币交易信息
type SubTransaction struct {
	ScTxid       string
	Amount       int64
	RechargeList []*AddressInfo //
	From         string         //from chain
	To           string         //to chain
	TokenFrom    uint32
	TokenTo      uint32
}

//Transaction 链上交易数据结构
type Transaction struct {
	BlockHash     string          //区块hash
	Confirmations uint64          //区块确认数
	ScTxid        string          //交易hash
	ScRawTxData   []byte          //交易原始数据
	SubTx         *SubTransaction //充币或熔币交易信息
}
