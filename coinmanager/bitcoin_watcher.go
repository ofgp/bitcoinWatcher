package coinmanager

import (
	"time"

	"github.com/btcsuite/btcd/wire"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
)

var defaultInterval = 1

func init() {
	viper.SetDefault("BTC.confirm_block_num", 6)
	viper.SetDefault("BTC.coinbase_confirm_block_num", 100)
	viper.SetDefault("BCH.confirm_block_num", 6)
	viper.SetDefault("BCH.coinbase_confirm_block_num", 100)
}

//BitCoinWatcher BTC/BCH监听类
type BitCoinWatcher struct {
	scanConfirmHeight     int64
	watchHeight           int64
	coinType              string
	bitcoinClient         *BitCoinClient
	confirmBlockChan      chan *BlockData
	newUnconfirmBlockChan chan *BlockData
	newTxChan             chan *wire.MsgTx
	confirmNeedNum        int64
	mempoolTxs            map[string]int
	//zmqClient             *zmq.Socket
	freshBlockList []*BlockData
}

//NewBitCoinWatcher 创建一个BTC/BCH监听实例
func NewBitCoinWatcher(coinType string, confirmHeight int64) (*BitCoinWatcher, error) {
	bw := BitCoinWatcher{
		scanConfirmHeight:     confirmHeight,
		coinType:              coinType,
		confirmBlockChan:      make(chan *BlockData, 32),
		newUnconfirmBlockChan: make(chan *BlockData, 32),
		newTxChan:             make(chan *wire.MsgTx, 100),
		mempoolTxs:            make(map[string]int),
		watchHeight:           -1,
		freshBlockList:        nil,
	}

	//bw.zmqClient, _ = zmq.NewSocket(zmq.SUB)
	switch coinType {
	case "btc":
		bw.confirmNeedNum = viper.GetInt64("BTC.confirm_block_num")
		//bw.zmqClient.Connect(viper.GetString("BTC.zmq_server"))
	case "bch":
		bw.confirmNeedNum = viper.GetInt64("BCH.confirm_block_num")
		//bw.zmqClient.Connect(viper.GetString("BCH.zmq_server"))

	}
	//bw.zmqClient.SetSubscribe("hashblock")
	bitcoinClient, err := NewBitCoinClient(coinType)
	if err != nil {
		log.Error("Create btc Client failed:", "err", err.Error())
		return &bw, err
	}
	bw.bitcoinClient = bitcoinClient

	return &bw, nil
}

//SetConfirmHeight 设置高度
func (bw *BitCoinWatcher) SetConfirmHeight(confirmHeight int64) {
	bw.scanConfirmHeight = confirmHeight
}

//GetConfirmChan 获取已确认区块chan
func (bw *BitCoinWatcher) GetConfirmChan() <-chan *BlockData {
	return bw.confirmBlockChan
}

//GetNewTxChan 获取交易CHAN
func (bw *BitCoinWatcher) GetNewTxChan() <-chan *wire.MsgTx {
	return bw.newTxChan
}

//GetNewUnconfirmBlockChan 获取新未确认区块CHAN
func (bw *BitCoinWatcher) GetNewUnconfirmBlockChan() <-chan *BlockData {
	return bw.newUnconfirmBlockChan
}

//WatchConfirmBlock 启动监听已确认区块
func (bw *BitCoinWatcher) WatchConfirmBlock() {

	go func() {

		for {
			blockHeight := bw.bitcoinClient.GetBlockCount()
			if blockHeight-bw.scanConfirmHeight+1 < bw.confirmNeedNum {
				time.Sleep(time.Duration(defaultInterval) * time.Second)
				continue
			}
			for {
				blockData := bw.bitcoinClient.GetBlockInfoByHeight(bw.scanConfirmHeight)
				if blockData == nil {
					break
				}

				isConfirm := bw.bitcoinClient.CheckIsConfirm(blockData)
				if !isConfirm {
					break
				}
				select {
				case bw.confirmBlockChan <- blockData:
					bw.scanConfirmHeight++
				default:
					time.Sleep(time.Duration(defaultInterval) * time.Second)
				}
			}
		}
	}()

}

//WatchNewTxFromNodeMempool 启动监听全节点内存中的新交易
func (bw *BitCoinWatcher) WatchNewTxFromNodeMempool() {

	go func() {
		for {
			txList, err := bw.bitcoinClient.GetRawMempool()
			if err != nil {
				log.Warn("GetRawMempool failed", "err", err.Error())
			}
			if len(txList) > 0 {
				log.Debug("mempool tx len", "len", len(txList))
				tempMap := make(map[string]int)

				for _, txID := range txList {
					tempMap[txID.String()] = 0

					_, ok := bw.mempoolTxs[txID.String()]
					if !ok {
						txEntity, err := bw.bitcoinClient.GetRawTransaction(txID.String())
						if err == nil {
							bw.newTxChan <- txEntity.MsgTx()
						}
					}
				}

				bw.mempoolTxs = tempMap
			}

			time.Sleep(time.Duration(defaultInterval) * time.Second)
		}
	}()

}

//WatchNewBlock 启动监听新区块
func (bw *BitCoinWatcher) WatchNewBlock() {

	/*
		go func() {
			wg.Add(1)
			defer func() {
				wg.Done()
			}()
			for {
				for {
					blockhash, err := bw.zmqClient.RecvBytes(0)
					if err != nil {
						log.Error("zmq err", "err", err.Error())
						break
					}
					log.Debug("get zmq hash", "hash", hex.EncodeToString(blockhash))
					if len(blockhash) != 32 {
						break
					}
					blockData := bw.bitcoinClient.GetBlockInfoByHash(hex.EncodeToString(blockhash))

					if blockData == nil {
						break
					}
					bw.newUnconfirmBlockChan <- blockData
					bw.watchHeight = blockData.BlockInfo.Height
				}
				time.Sleep(time.Millisecond)
			}
		}()
	*/

	go func() {

		for {
			blockHeight := bw.bitcoinClient.GetBlockCount()
			//log.Debug("Check block count", "block_height", blockHeight)

			var watchHeight int64
			if bw.freshBlockList != nil {
				watchHeight = bw.freshBlockList[len(bw.freshBlockList)-1].BlockInfo.Height
			} else {
				watchHeight = blockHeight - 1
			}

			//log.Debug("watchHeight", "watchHeight", watchHeight)

			if blockHeight <= watchHeight {
				time.Sleep(time.Duration(defaultInterval) * time.Second)
				continue
			}

			for {
				blockData := bw.bitcoinClient.GetBlockInfoByHeight(watchHeight + 1)
				log.Debug("get block index", "index", watchHeight+1)

				if blockData == nil {
					break
				}

				if len(bw.freshBlockList) > 0 {
					preHash := bw.freshBlockList[len(bw.freshBlockList)-1].BlockInfo.Hash
					if blockData.BlockInfo.PreviousHash != preHash {
						log.Debug("hash not equal", "prehash", preHash, "newblockprehash", blockData.BlockInfo.PreviousHash)
						bw.freshBlockList = bw.freshBlockList[:len(bw.freshBlockList)-1]
						watchHeight--
						continue
					}
				}

				bw.freshBlockList = append(bw.freshBlockList, blockData)

				if int(blockData.BlockInfo.Confirmations) < int(bw.confirmNeedNum) {
					bw.newUnconfirmBlockChan <- blockData
				}

				watchHeight = bw.freshBlockList[len(bw.freshBlockList)-1].BlockInfo.Height

				if len(bw.freshBlockList) >= int(bw.confirmNeedNum) {
					bw.freshBlockList = bw.freshBlockList[1:]
				}
				log.Debug("freshBlockList len", "len", len(bw.freshBlockList))

				if watchHeight >= blockHeight {
					break
				}
			}
			/*
				for index := bw.watchHeight + 1; index <= blockHeight; index++ {
					blockData := bw.bitcoinClient.GetBlockInfoByHeight(index)
					log.Debug("get block index", "index", index)
					if blockData == nil {
						break
					}
					bw.newUnconfirmBlockChan <- blockData
					bw.watchHeight = blockData.BlockInfo.Height
				}
			*/
		}
	}()

}

//GetBitCoinClient 获取BTC/BCH客户端
func (bw *BitCoinWatcher) GetBitCoinClient() *BitCoinClient {
	return bw.bitcoinClient
}
