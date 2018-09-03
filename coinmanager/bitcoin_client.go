package coinmanager

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("BTC.confirm_block_num", 6)
	viper.SetDefault("BTC.coinbase_confirm_block_num", 100)
	viper.SetDefault("BCH.confirm_block_num", 6)
	viper.SetDefault("BCH.coinbase_confirm_block_num", 100)
}

//BitCoinClient BTC/BCH RPC操作类
type BitCoinClient struct {
	rpcClient  *rpcclient.Client
	confirmNum uint64
}

//NewBitCoinClient 创建一个bitcoin操作客户端
func NewBitCoinClient(coinType string) (*BitCoinClient, error) {
	connCfg := &rpcclient.ConnConfig{
		HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
		DisableTLS:   true, // Bitcoin core does not provide TLS by default
	}
	bc := &BitCoinClient{}

	switch coinType {
	case "btc":
		connCfg.Host = viper.GetString("BTC.rpc_server")
		connCfg.User = viper.GetString("BTC.rpc_user")
		connCfg.Pass = viper.GetString("BTC.rpc_password")
		bc.confirmNum = uint64(viper.GetInt64("BTC.confirm_block_num"))
	case "bch":
		connCfg.Host = viper.GetString("BCH.rpc_server")
		connCfg.User = viper.GetString("BCH.rpc_user")
		connCfg.Pass = viper.GetString("BCH.rpc_password")
		bc.confirmNum = uint64(viper.GetInt64("BCH.confirm_block_num"))
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Error("GET_BTC_RPC_CLIENT FAIL:", "err", err.Error())
	}

	bc.rpcClient = client

	return bc, err
}

//CheckIsConfirm 检查区块确认数是否超过N个块
func (b *BitCoinClient) CheckIsConfirm(blockData *BlockData) bool {
	if blockData.BlockInfo.Confirmations >= b.confirmNum {
		return true
	}
	return false

}

//CheckTxIsConfirm 检查交易确认数是否超过N个块
func (b *BitCoinClient) CheckTxIsConfirm(txHash string) bool {
	tx, err := b.GetRawTransactionVerbose(txHash)
	if err != nil || tx == nil {
		return false
	}
	if tx.Confirmations >= b.confirmNum {
		return true
	}
	return false
}

//GetBlockCount 获取当前区块链高度
func (b *BitCoinClient) GetBlockCount() int64 {
	blockHeight, err := b.rpcClient.GetBlockCount()
	if err != nil {
		log.Warn("GET_BLOCK_COUNT FAIL:", "err", err.Error())
		return -1
	}
	return blockHeight
}

//GetRawTransaction 根据txhash从区块链上查询交易数据
func (b *BitCoinClient) GetRawTransaction(txHash string) (*btcutil.Tx, error) {
	hash, err := chainhash.NewHashFromStr(txHash)
	if err != nil {
		log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", txHash)
		return nil, err
	}

	txRaw, err := b.rpcClient.GetRawTransaction(hash)
	if err != nil {
		log.Warn("GetRawTransaction FAILED:", "err", err.Error(), "hash", txHash)
		return nil, err
	}
	return txRaw, nil
}

//GetRawTransactionVerbose 根据txhash从区块链上查询交易数据（包含区块信息）
func (b *BitCoinClient) GetRawTransactionVerbose(txHash string) (*btcjson.TxRawResult, error) {
	hash, err := chainhash.NewHashFromStr(txHash)
	if err != nil {
		log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", txHash)
		return nil, err
	}

	txRaw, err := b.rpcClient.GetRawTransactionVerbose(hash)
	if err != nil {
		log.Warn("GetRawTransactionVerbose FAILED:", "err", err.Error(), "hash", txHash)
		return nil, err
	}
	return txRaw, nil
}

//GetRawMempool 从全节点内存中获取内存中的交易数据
func (b *BitCoinClient) GetRawMempool() ([]*chainhash.Hash, error) {
	result, err := b.rpcClient.GetRawMempool()
	if err != nil {
		log.Warn("GetRawMempool FAILED:", "err", err.Error())
		return nil, err
	}
	return result, err
}

//GetBlockInfoByHeight 根据区块高度获取区块信息
func (b *BitCoinClient) GetBlockInfoByHeight(height int64) *BlockData {
	blockHash, err := b.rpcClient.GetBlockHash(height)
	if err != nil {
		log.Warn("GET_BLOCK_HASH FAIL:", "err", err.Error())
		return nil
	}

	blockVerbose, err := b.rpcClient.GetBlockVerbose(blockHash)
	if err != nil {
		log.Warn("GET_BLOCK_VERBOSE FAIL:", "err", err.Error())
		return nil
	}

	blockEntity, err := b.rpcClient.GetBlock(blockHash)
	if err != nil {
		log.Warn("GET_BLOCK FAIL:", "err", err.Error())
		return nil
	}

	return &BlockData{
		BlockInfo: blockVerbose,
		MsgBolck:  blockEntity,
	}
}

//GetBlockInfoByHash 根据区块hash获取区块信息
func (b *BitCoinClient) GetBlockInfoByHash(hash string) *BlockData {
	blockHash, err := chainhash.NewHashFromStr(hash)
	if err != nil {
		log.Warn("GET_BLOCK_HASH FAIL:", "err", err.Error())
		return nil
	}

	blockVerbose, err := b.rpcClient.GetBlockVerbose(blockHash)
	if err != nil {
		log.Warn("GET_BLOCK_VERBOSE FAIL:", "err", err.Error(), "hash", blockHash.String())
		return nil
	}

	blockEntity, err := b.rpcClient.GetBlock(blockHash)
	if err != nil {
		log.Warn("GET_BLOCK FAIL:", "err", err.Error())
		return nil
	}

	return &BlockData{
		BlockInfo: blockVerbose,
		MsgBolck:  blockEntity,
	}
}

//SendRawTransaction 发送交易数据到全节点
func (b *BitCoinClient) SendRawTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	return b.rpcClient.SendRawTransaction(tx, true)
}

//EstimateFee 评估交易矿工费
func (b *BitCoinClient) EstimateFee(numBlocks int64) (int64, error) {
	fee, err := b.rpcClient.EstimateFee(numBlocks)
	if err != nil {
		return 0, err
	}

	return int64(fee * 1E8), err

}

func (b *BitCoinClient) ImportAddress(address string) error {
	return b.rpcClient.ImportAddressRescan(address, false)
}

func (b *BitCoinClient) ListUnspent(address []btcutil.Address) ([]btcjson.ListUnspentResult, error) {
	return b.rpcClient.ListUnspentMinMaxAddresses(0, 999999, address)
}
