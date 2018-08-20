package coinmanager

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
)

//BlockData 区块数据
type BlockData struct {
	BlockInfo *btcjson.GetBlockVerboseResult
	MsgBolck  *wire.MsgBlock
}

//UtxoInfo UTXO数据spend_type: -1:failed; 0:unconfirm; 1: unspent 2:using 3:spent 4:临时占用中
type UtxoInfo struct {
	Address      string `json:"address"`
	VoutTxid     string `json:"vout_txid"`
	VoutIndex    uint32 `json:"vout_index"`
	Value        int64  `json:"value"`
	VoutPkscript string `json:"vout_pkscript"`
	SpendType    int32  `json:"spend_type"`
	VinTxid      string `json:"vin_txid"`
	BlockHeight  int64  `json:"block_height"`
	IsCoinBase   bool   `json:"is_coinbase"`
}

//VinInfo 交易输入数据
type VinInfo struct {
	PreTxid         string `json:"pre_txid"`
	PreTxidVout     uint32 `json:"pre_txid_vout"`
	PreVoutValue    int64  `json:"pre_vout_value"`
	SignatureScript string `json:"signature_script"`
	InputAddress    string `json:"input_address"`
	Sequence        uint32 `json:"sequence"`
}

//VoutInfo 交易输出数据
type VoutInfo struct {
	VoutValue     int64  `json:"vout_value"`
	OutputAddress string `json:"output_address"`
	PkScript      string `json:"pk_script"`
}

//TxInfo 交易数据status 0: pending 1:confirm 2:failed 3: inblock
type TxInfo struct {
	BlockHash   string      `json:"block_hash"`
	BlockHeight int64       `json:"block_height"`
	BlockTime   int64       `json:"block_time"`
	Txid        string      `json:"txid"`
	TxidIndex   int32       `json:"txid_index"`
	Version     int32       `json:"version"`
	Size        int32       `json:"size"`
	Locktime    uint32      `json:"locktime"`
	Status      int32       `json:"status"`
	Vin         []*VinInfo  `json:"vin"`
	Vout        []*VoutInfo `json:"vout"`
}

type UtxoSorter struct {
	UtxoList       []*UtxoInfo
	MaxBlockHeight int64
}

func (u *UtxoSorter) Len() int {
	return len(u.UtxoList)
}

func (u *UtxoSorter) Less(i, j int) bool {
	if u.UtxoList[i].SpendType != u.UtxoList[j].SpendType {
		return u.UtxoList[i].SpendType > u.UtxoList[j].SpendType
	}

	//
	priorityI := 0
	if u.MaxBlockHeight-u.UtxoList[i].BlockHeight > 0 {
		priorityI = 1
	}

	priorityJ := 0
	if u.MaxBlockHeight-u.UtxoList[j].BlockHeight > 0 {
		priorityJ = 1
	}

	if priorityI != priorityJ {
		return priorityI > priorityJ
	}

	return u.UtxoList[i].Value < u.UtxoList[j].Value
}

func (u *UtxoSorter) Swap(i, j int) {
	u.UtxoList[i], u.UtxoList[j] = u.UtxoList[j], u.UtxoList[i]
}
