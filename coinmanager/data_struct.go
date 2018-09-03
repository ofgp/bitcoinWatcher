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

type UtxoInfo struct {
	Address       string `json:"address"`
	Txid          string `json:"vout_txid"`
	Vout          uint32 `json:"vout_index"`
	Value         int64  `json:"value"`
	Confirmations int64  `json:"confirmations"`
}

type UtxoList []*UtxoInfo

func (u UtxoList) Len() int      { return len(u) }
func (u UtxoList) Swap(i, j int) { u[i], u[j] = u[j], u[i] }
func (u UtxoList) Less(i, j int) bool {
	priorityI := 0
	priorityJ := 0

	if u[i].Confirmations > 0 {
		priorityI = 1
	}

	if u[j].Confirmations > 0 {
		priorityJ = 1
	}

	if priorityI != priorityJ {
		return priorityI > priorityJ
	}

	return u[i].Value < u[j].Value
}
