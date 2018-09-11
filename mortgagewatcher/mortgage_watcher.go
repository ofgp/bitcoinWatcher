package mortgagewatcher

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcutil"

	"github.com/ofgp/bitcoinWatcher/coinmanager"
	"github.com/ofgp/bitcoinWatcher/dbop"
	"github.com/ofgp/bitcoinWatcher/util"
	"github.com/shopspring/decimal"

	"github.com/btcsuite/btcd/btcjson"

	"github.com/spf13/viper"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cpacia/bchutil"
	log "github.com/inconshreveable/log15"
)

var (
	confirmHeightLDKey = "confirmHeight"
	syncInterval       = 2
)

func init() {
	homeDir, _ := util.GetHomeDir()
	dbPath := path.Join(homeDir, "btc_db")
	viper.SetDefault("LEVELDB.btc_db_path", dbPath)
	dbPath = path.Join(homeDir, "bch_db")
	viper.SetDefault("LEVELDB.bch_db_path", dbPath)

}

//MortgageWatcher 抵押交易监听类
type MortgageWatcher struct {
	sync.Mutex
	bwClient          *coinmanager.BitCoinWatcher
	scanConfirmHeight int64
	coinType          string
	mortgageTxChan    chan *SubTransaction
	federationAddress string
	redeemScript      []byte
	levelDb           *dbop.LDBDatabase
	utxoMonitorCount  sync.Map
	federationMap     sync.Map
	addrList          []btcutil.Address
	timeout           int
	confirmNum        int64

	levelDbTxMappingPreFix string
	levelDbTxPreFix        string
	levelDbUtxoPreFix      string
}

func openLevelDB(coinType string) (*dbop.LDBDatabase, error) {
	dbPath := viper.GetString("LEVELDB.bch_db_path")
	if coinType == "btc" {
		dbPath = viper.GetString("LEVELDB.btc_db_path")
	}

	info, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		if err := os.Mkdir(dbPath, 0700); err != nil {
			return nil, err
		}
	} else {
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, err
		}
	}

	db, err := dbop.NewLDBDatabase(dbPath, 16, 16)
	if err != nil {
		return nil, err
	}
	return db, nil

}

//NewMortgageWatcher 创建一个抵押交易监听实例
//coinType bch/btc, confirmHeight监听开始的高度， federationAddress 要监听的多签地址 redeemScript兑现脚本
func NewMortgageWatcher(coinType string, confirmHeight int64, federationAddress string, redeemScript []byte, timeout int) (*MortgageWatcher, error) {

	levelDb, err := openLevelDB(coinType)
	if err != nil {
		log.Error("open level db failed", "err", err.Error())
		return nil, err
	}

	//查看leveldb存储的高度
	height := 0

	value, err := levelDb.Get([]byte(confirmHeightLDKey))
	if value != nil && err == nil {
		height, err = strconv.Atoi(string(value))
		if err != nil {
			log.Error("atoi height failed", "err", err.Error())
			return nil, err
		}
	}

	log.Debug("confirm height", "height", height)

	if int64(height) >= confirmHeight {
		confirmHeight = int64(height)
	}

	bwClient, err := coinmanager.NewBitCoinWatcher(coinType, confirmHeight)
	if err != nil {
		return nil, err
	}

	mw := MortgageWatcher{
		levelDb:           levelDb,
		bwClient:          bwClient,
		scanConfirmHeight: confirmHeight,
		coinType:          coinType,
		mortgageTxChan:    make(chan *SubTransaction, 100),
		federationAddress: federationAddress,
		redeemScript:      redeemScript,
		timeout:           timeout,
	}

	switch coinType {
	case "btc":
		mw.confirmNum = int64(viper.GetInt64("BTC.confirm_block_num"))
	case "bch":
		mw.confirmNum = int64(viper.GetInt64("BCH.confirm_block_num"))
	}

	mw.federationMap.Store(federationAddress, redeemScript)
	addr, err := coinmanager.DecodeAddress(federationAddress, coinType)
	if err != nil {
		log.Warn("decode address failed", "err", err.Error())
		return nil, err
	}
	mw.addrList = append(mw.addrList, addr)

	err = mw.bwClient.GetBitCoinClient().ImportAddress(federationAddress)
	if err != nil {
		log.Warn("Import address failed", "err", err.Error(), "coinType", coinType)
		return nil, err
	}

	mw.levelDbUtxoPreFix = strings.Join([]string{coinType, "utxo"}, "_")
	mw.levelDbTxPreFix = strings.Join([]string{coinType, "fa_tx"}, "_")
	mw.levelDbTxMappingPreFix = strings.Join([]string{coinType, "hash_mapping"}, "_")

	return &mw, err
}

func (m *MortgageWatcher) utxoMonitor() {
	go func() {
		for {
			m.utxoMonitorCount.Range(func(k, v interface{}) bool {
				utxoID := k.(string)
				count := v.(int)
				count++
				if count >= m.timeout {
					m.utxoMonitorCount.Delete(utxoID)
				} else {
					m.utxoMonitorCount.Store(utxoID, count)
				}
				return true
			})

			time.Sleep(time.Duration(1) * time.Second)
		}
	}()
}

//GetBlockNumber 获取当前已监听到的区块
func (m *MortgageWatcher) GetBlockNumber() int64 {
	return m.scanConfirmHeight
}

//GetFederationAddress 获取联盟多签地址
func (m *MortgageWatcher) GetFederationAddress() string {
	return m.federationAddress
}

//checkIsFromFederation 检查交易是否是网关发出
func (m *MortgageWatcher) checkIsFromFederation(txid string) bool {
	txKey := strings.Join([]string{m.levelDbTxPreFix, txid}, "_")

	realHash, err := m.levelDb.Get([]byte(txKey))
	if realHash != nil && err == nil {
		return true
	}
	return false
}

//syncUtxoInfo 从全节点获取更新utxo进leveldb
func (m *MortgageWatcher) syncUtxoInfo() {
	go func() {
		lastUtxoSnapShot := make(map[string]*coinmanager.UtxoInfo)
		for {
			tempUtxo := make(map[string]*coinmanager.UtxoInfo)
			utxoList, err := m.bwClient.GetBitCoinClient().ListUnspent(m.addrList)
			if err != nil {
				log.Warn("listunspent failed")
				time.Sleep(time.Duration(syncInterval) * time.Second)
				continue
			}

			for _, utxo := range utxoList {
				utxoID := strings.Join([]string{utxo.TxID, strconv.Itoa(int(utxo.Vout))}, "_")
				value := decimal.NewFromFloat(utxo.Amount).Mul(decimal.NewFromFloat(1E8)).IntPart()
				utxoInfo := &coinmanager.UtxoInfo{
					Address:       utxo.Address,
					Txid:          utxo.TxID,
					Vout:          utxo.Vout,
					Value:         value,
					Confirmations: utxo.Confirmations,
				}
				tempUtxo[utxoID] = utxoInfo
				if _, ok := lastUtxoSnapShot[utxoID]; ok {
					continue
				}

				log.Debug("utxo info", "amount", utxo, "value", utxoInfo.Value)

				data, err := json.Marshal(utxoInfo)
				if err != nil {
					log.Warn("Marshal utxo failed", "err", err.Error(), "coinType", m.coinType)
					continue
				}

				key := strings.Join([]string{m.levelDbUtxoPreFix, utxoID}, "_")

				retErr := m.levelDb.Put([]byte(key), []byte(data))
				if retErr != nil {
					log.Warn("Marshal utxo failed", "err", err.Error(), "coinType", m.coinType)
					continue
				}
			}
			lastUtxoSnapShot = tempUtxo
			time.Sleep(time.Duration(syncInterval) * time.Second)
		}
	}()
}

//getUtxoInfo 从leveldb中获取utxo信息
func (m *MortgageWatcher) GetUtxoInfoByID(utxoID string) *coinmanager.UtxoInfo {
	Key := strings.Join([]string{m.levelDbUtxoPreFix, utxoID}, "_")

	utxodata, err := m.levelDb.Get([]byte(Key))
	if utxodata != nil && err == nil {
		utxo := &coinmanager.UtxoInfo{}
		err := json.Unmarshal(utxodata, utxo)
		if err != nil {
			log.Warn("Unmarshal UTXO FROM LEVELDB ERR", "err", err.Error(), "coinType", m.coinType)
			return nil
		}

		return utxo
	}
	return nil
}

//GetUnspentUtxo 获得指定地址未花费的utxo
func (m *MortgageWatcher) GetUnspentUtxo(address string) coinmanager.UtxoList {
	var retList coinmanager.UtxoList

	addr, err := coinmanager.DecodeAddress(address, m.coinType)
	if err != nil {
		return retList
	}

	utxoList, err := m.bwClient.GetBitCoinClient().ListUnspent([]btcutil.Address{addr})
	if err != nil {
		return retList
	}

	for _, utxo := range utxoList {
		utxoID := strings.Join([]string{utxo.TxID, strconv.Itoa(int(utxo.Vout))}, "_")
		//临时占用中
		_, ok := m.utxoMonitorCount.Load(utxoID)
		if ok {
			continue
		}

		//utxo小于确认数并且不是网关发出
		if utxo.Confirmations < m.confirmNum && !m.checkIsFromFederation(utxo.TxID) {
			continue
		}

		value := decimal.NewFromFloat(utxo.Amount).Mul(decimal.NewFromFloat(1E8)).IntPart()
		//value, _ := new(big.Float).Mul(new(big.Float).SetFloat64(utxo.Amount), new(big.Float).SetFloat64(1E8)).Int64()
		utxoInfo := &coinmanager.UtxoInfo{
			Address:       utxo.Address,
			Txid:          utxo.TxID,
			Vout:          utxo.Vout,
			Value:         value,
			Confirmations: utxo.Confirmations,
		}
		log.Debug("utxo info", "amount", utxo, "value", utxoInfo.Value)
		retList = append(retList, utxoInfo)
	}

	return retList
}

//ChangeFederationAddress 修改多签地址
func (m *MortgageWatcher) ChangeFederationAddress(federationAddress string, redeemScript []byte) bool {
	m.Lock()
	defer m.Unlock()
	m.federationAddress = federationAddress
	m.redeemScript = redeemScript
	m.federationMap.Store(federationAddress, redeemScript)
	addr, err := coinmanager.DecodeAddress(federationAddress, m.coinType)
	if err != nil {
		log.Warn("decode address failed", "err", err.Error())
		return false
	}
	m.addrList = append(m.addrList, addr)

	err = m.bwClient.GetBitCoinClient().ImportAddress(federationAddress)
	if err != nil {
		log.Warn("Import address failed", "err", err.Error(), "coinType", m.coinType)
		return false
	}

	return true

}

//TransferAsset 从指定地址迁移资产到新多签地址。
func (m *MortgageWatcher) TransferAsset(address string, sigNum int, NodeNum int) *wire.MsgTx {
	m.Lock()
	defer m.Unlock()

	//估算每个输入签名的长度(略加长)
	sigNum = 10 + 73*sigNum + 66*NodeNum
	log.Debug("Estimate sig", "len", sigNum)

	unspentUtxoList := m.GetUnspentUtxo(address)

	tx := wire.NewMsgTx(1)

	count := 0
	var coinSum int64
	for _, selectCoin := range unspentUtxoList {
		hash, err := chainhash.NewHashFromStr(selectCoin.Txid)
		if err != nil {
			log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", hash, "coinType", m.coinType)
			return nil
		}

		utxoID := strings.Join([]string{selectCoin.Txid, strconv.Itoa(int(selectCoin.Vout))}, "_")
		log.Debug("select coin", "utxo_id", utxoID, "coinType", m.coinType)

		m.utxoMonitorCount.Store(utxoID, 0)

		vin := wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: selectCoin.Vout,
			},
		}

		tx.AddTxIn(&vin)
		coinSum += selectCoin.Value
		count++
		if count >= 10 {
			break
		}
	}

	//估算fee值
	bitcoinClient := m.bwClient.GetBitCoinClient()
	feePerKB, err := bitcoinClient.EstimateFee(6)
	if err != nil {
		log.Error("get fee/kb failed", "err", err.Error())
		return nil
	}
	if feePerKB < 0 {
		feePerKB = 1000
	}

	decodeAddr, err := coinmanager.DecodeAddress(m.federationAddress, m.coinType)
	if err != nil {
		log.Warn("DecodeAddress failed", "err", err.Error(), "coinType", m.coinType)
		return nil
	}
	pkScript, err := bchutil.PayToAddrScript(decodeAddr)
	if err != nil {
		log.Warn("PayToAddrScript failed", "err", err.Error(), "coinType", m.coinType)
		return nil
	}

	vout := &wire.TxOut{
		Value:    coinSum,
		PkScript: pkScript,
	}

	tx.AddTxOut(vout)

	fee := int64(tx.SerializeSize()+sigNum*count) * feePerKB / 1000
	if fee < 1000 {
		fee = 1000
	}

	if coinSum-fee <= 0 {
		log.Error("can't pay fee")
		return nil
	}

	log.Debug("check tx", "coinSum", coinSum, "feePerKb", feePerKB, "size", tx.SerializeSize(), "fee", fee)

	vout.Value = coinSum - fee

	return tx
}

//GetTxChan 获取抵押交易CHAN,监听程序每监听到一个抵押交易放到chan中
func (m *MortgageWatcher) GetTxChan() <-chan *SubTransaction {
	return m.mortgageTxChan
}

//CreateCoinTx 创建提币交易数据
//功能：根据提币地址和提币金额，拉取联盟地址可用UTXO创建提币交易数据
//输入： addrList： 提币地址与金额
//输出： 交易数据
func (m *MortgageWatcher) CreateCoinTx(addrList []*AddressInfo, sigNum int, NodeNum int) (*wire.MsgTx, int) {
	m.Lock()
	defer m.Unlock()

	var totalValue int64

	for _, addrInfo := range addrList {
		totalValue += addrInfo.Amount
	}

	//miner fee
	feePerKB, err := m.bwClient.GetBitCoinClient().EstimateFee(6)
	if err != nil {
		log.Error("get fee/kb failed", "err", err.Error())
		return nil, 1
	}

	log.Debug("fee/kb", "fee", feePerKB)

	if feePerKB <= 0 {
		feePerKB = 1000
	}

	minFee := feePerKB
	unspentUtxoList := m.GetUnspentUtxo(m.federationAddress)
	log.Debug("utxolist", "len", len(unspentUtxoList))

	//tx create
	tx := wire.NewMsgTx(2)

	for {
		selectCoinList, coinSum := coinmanager.CoinSelect(unspentUtxoList, totalValue+minFee)
		log.Debug("selectCoinList", "len", len(selectCoinList), "coinSum", coinSum)

		if coinSum < totalValue+minFee {
			log.Warn("COIN NOT ENOUGH", "coinType", m.coinType)
			return nil, 1
		}

		//估算交易大小
		voutLen := (len(addrList) + 1) * 40
		vinLen := len(selectCoinList) * (40 + 10 + 73*sigNum + 66*NodeNum)
		txLen := 8 + wire.VarIntSerializeSize(uint64(len(selectCoinList))) + wire.VarIntSerializeSize(uint64(len(addrList)+1)) + voutLen + vinLen
		minFee = feePerKB * int64(txLen) / 1000
		if minFee < 1000 {
			minFee = 1000
		}

		if coinSum >= totalValue+minFee {
			//找零
			if coinSum-totalValue-minFee > 546 {
				smallChange := AddressInfo{
					Address: m.federationAddress,
					Amount:  coinSum - totalValue - minFee,
				}
				addrList = append(addrList, &smallChange)
			}

			for _, addrInfo := range addrList {
				decodeAddr, err := coinmanager.DecodeAddress(addrInfo.Address, m.coinType)
				if err != nil {
					log.Warn("DecodeAddress failed", "err", err.Error(), "coinType", m.coinType)
					return nil, 2
				}
				pkScript, err := bchutil.PayToAddrScript(decodeAddr)
				if err != nil {
					log.Warn("PayToAddrScript failed", "err", err.Error(), "coinType", m.coinType)
					return nil, 2
				}

				vout := wire.TxOut{
					Value:    addrInfo.Amount,
					PkScript: pkScript,
				}
				tx.AddTxOut(&vout)
			}

			//new vin
			for _, selectCoin := range selectCoinList {
				hash, err := chainhash.NewHashFromStr(selectCoin.Txid)
				if err != nil {
					log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", hash, "coinType", m.coinType)
					return nil, 100
				}

				utxoID := strings.Join([]string{selectCoin.Txid, strconv.Itoa(int(selectCoin.Vout))}, "_")
				log.Debug("select coin", "utxo_id", utxoID, "coinType", m.coinType)
				m.utxoMonitorCount.Store(utxoID, 0)

				vin := wire.TxIn{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *hash,
						Index: selectCoin.Vout,
					},
				}
				tx.AddTxIn(&vin)
			}

			return tx, 0
		}
	}
}

//SignTx 对交易数据签名，返回交易签名
func (m *MortgageWatcher) SignTx(tx *wire.MsgTx, nodePubKeyHash string) ([][]byte, int) {

	var sigs [][]byte

	for i, vin := range tx.TxIn {
		utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
		utxoInfo := m.GetUtxoInfoByID(utxoID)
		m.utxoMonitorCount.Store(utxoID, 0)

		if utxoInfo != nil {
			rs, rsok := m.federationMap.Load(utxoInfo.Address)
			if rsok {
				redeemScript := rs.([]byte)
				sig, err := coinmanager.RawTxInSignature(tx, i, redeemScript, txscript.SigHashAll,
					utxoInfo.Value, m.coinType, nodePubKeyHash,
				)
				log.Debug("utxoInfo", "utxoInfo", utxoInfo.Value)
				if err != nil {
					return sigs, 3
				}
				sigs = append(sigs, sig)

			} else {
				return sigs, 2
			}

		} else {
			log.Warn("Can't find utxoInfo", "utxoID", utxoID)
			return sigs, 1
		}
	}

	return sigs, 0
}

//MergeSignTx 合并多组节点签名
func (m *MortgageWatcher) MergeSignTx(tx *wire.MsgTx, sigsList [][][]byte) bool {

	for i, vin := range tx.TxIn {
		utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
		utxoInfo := m.GetUtxoInfoByID(utxoID)
		m.utxoMonitorCount.Store(utxoID, 0)
		if utxoInfo == nil {
			log.Warn("【MergeSignTx】CAN'T FIND UTXO", "utxo", utxoID)
			return false
		}

		rs, rsok := m.federationMap.Load(utxoInfo.Address)
		if !rsok {
			log.Warn("【MergeSignTx】CAN'T FIND Address", "Address", utxoInfo.Address)
			return false
		}

		redeemScript := rs.([]byte)

		builder := txscript.NewScriptBuilder().AddOp(txscript.OP_FALSE)
		for index, sigs := range sigsList {
			if len(sigs) != len(tx.TxIn) {
				log.Warn("【MergeSignTx】sign len not equal txIn len", "sign index", index, "sign len", len(sigs), "tx len", len(tx.TxIn))
				return false
			}
			builder.AddData(sigs[i])
		}
		realSigScript, _ := builder.Script()

		builder2 := txscript.NewScriptBuilder()
		builder2.AddOps(realSigScript)
		builder2.AddData(redeemScript)
		tx.TxIn[i].SignatureScript, _ = builder2.Script()

	}

	return true
}

//VerifySign 验证交易签名是否正确, true表示验签正确， false表示验签失败
func (m *MortgageWatcher) VerifySign(tx *wire.MsgTx, sigs [][]byte, pubKey []byte) bool {
	if len(sigs) != len(tx.TxIn) {
		log.Warn("【VerifySign】sign len not equal txIn len", "sign len", len(sigs), "tx len", len(tx.TxIn))
		return false
	}
	pk, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		log.Error("【VerifySign】ParsePubKey err", "err", err.Error(), "coinType", m.coinType)
		return false
	}

	for i, vin := range tx.TxIn {
		sig := sigs[i]
		tSig := sig[:len(sig)-1]
		hashType := txscript.SigHashType(sig[len(sig)-1])

		pSig, err := btcec.ParseDERSignature(tSig, btcec.S256())
		if err != nil {
			log.Error("【VerifySign】ParseDERSignature err", "sig", hex.EncodeToString(sig), "coinType", m.coinType)
			return false
		}

		var hash []byte

		utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
		utxoInfo := m.GetUtxoInfoByID(utxoID)
		m.utxoMonitorCount.Store(utxoID, 0)
		if utxoInfo != nil {
			rs, rsok := m.federationMap.Load(utxoInfo.Address)
			if !rsok {
				log.Warn("【VerifySign】CAN'T FIND Address", "Address", utxoInfo.Address)
				return false
			}

			redeemScript := rs.([]byte)

			if m.coinType == "bch" {
				hash = coinmanager.CalcBip143SignatureHash(redeemScript, txscript.NewTxSigHashes(tx), hashType, tx, i, utxoInfo.Value)
			} else {
				hash, _ = txscript.CalcSignatureHash(redeemScript, hashType, tx, i)
			}
		} else {
			log.Warn("【VerifySign】CAN'T FIND UTXO", "utxoID", utxoID)
			return false
		}

		if !pSig.Verify(hash, pk) {
			return false
		}

	}

	return true
}

//SendTx 发送交易到链上
func (m *MortgageWatcher) SendTx(tx *wire.MsgTx) (string, *btcjson.RPCError) {
	bitcoinClient := m.bwClient.GetBitCoinClient()
	hash, err := bitcoinClient.SendRawTransaction(tx)
	if err != nil {
		e := btcjson.NewRPCError(0, "")
		if reflect.TypeOf(err).String() == reflect.TypeOf(e).String() {
			e.Code = err.(*btcjson.RPCError).Code
			e.Message = err.(*btcjson.RPCError).Message
		} else {
			e.Code = -100
			e.Message = err.Error()
		}
		return "", e

	}
	return hash.String(), nil
}

//GetTxByHash 通过交易hash从链上查询交易数据，查询提币交易通过签名前的交易HASH来查询（以保障各节点可独立验证，不依赖主节点发送的交易HASH）
//查询抵押交易使用链上的交易HASH查询。
func (m *MortgageWatcher) GetTxByHash(hash string) *Transaction {
	key := strings.Join([]string{m.levelDbTxMappingPreFix, hash}, "_")

	realHash, err := m.levelDb.Get([]byte(key))
	if realHash != nil && err == nil {
		hash = string(realHash)
	}

	bitcoinClient := m.bwClient.GetBitCoinClient()
	tx, err := bitcoinClient.GetRawTransaction(hash)

	if err != nil {
		log.Warn("GetRawTransaction failed", "err", err.Error(), "hash", hash, "coinType", m.coinType)
		return nil
	}

	var buf bytes.Buffer
	err1 := tx.MsgTx().SerializeNoWitness(&buf)
	if err1 != nil {
		log.Warn("SerializeNoWitness failed", "err", err1.Error(), "hash", hash, "coinType", m.coinType)
		return nil
	}

	txVerbose, err := bitcoinClient.GetRawTransactionVerbose(hash)
	if err != nil {
		log.Warn("GetRawTransactionVerbose failed", "err", err.Error(), "hash", hash, "coinType", m.coinType)
		return nil
	}

	hasReturn := false
	isFedAddr := false
	var value int64
	var message *Message

	for _, vout := range tx.MsgTx().TxOut {
		address := coinmanager.ExtractPkScriptAddr(vout.PkScript, m.coinType)
		if address != "" {
			if _, ok := m.federationMap.Load(address); ok {
				isFedAddr = true
				value = vout.Value

			}
		} else {
			message, err = ParserPayLoadScript(vout.PkScript)
			if err == nil {
				hasReturn = true
			}

		}
	}

	retTx := Transaction{
		BlockHash:     txVerbose.BlockHash,
		Confirmations: txVerbose.Confirmations,
		ScTxid:        txVerbose.Hash,
		ScRawTxData:   buf.Bytes(),
	}

	// make mortgage tx
	if isFedAddr && hasReturn {
		mortgageTx := SubTransaction{
			ScTxid:    tx.MsgTx().TxHash().String(),
			Amount:    value,
			From:      m.coinType,
			To:        message.ChainName,
			TokenFrom: 0,
			TokenTo:   message.APPNumber,
			RechargeList: []*AddressInfo{
				{
					Address: message.Address,
					Amount:  value,
				},
			},
		}
		retTx.SubTx = &mortgageTx
	}

	return &retTx
}

//存储tx 签名前与签名后的交易hash映射
func (m *MortgageWatcher) storeHashMapping(tx *wire.MsgTx) bool {
	hashAfterSign := tx.TxHash().String()

	copyTx := tx.Copy()
	for _, vin := range copyTx.TxIn {
		vin.SignatureScript = nil
	}
	hashBeforeSign := copyTx.TxHash().String()
	mappingKey := strings.Join([]string{m.levelDbTxMappingPreFix, hashBeforeSign}, "_")
	log.Debug("storeHashMap", "hash_before_sign", hashBeforeSign, "hash_after_sign", hashAfterSign, "coinType", m.coinType)

	retErr := m.levelDb.Put([]byte(mappingKey), []byte(hashAfterSign))
	if retErr != nil {
		log.Warn("save hashmap failed", "err", retErr.Error(), "coinType", m.coinType)
		return false
	}

	txKey := strings.Join([]string{m.levelDbTxPreFix, hashAfterSign}, "_")
	retErr = m.levelDb.Put([]byte(txKey), []byte(hashAfterSign))
	if retErr != nil {
		log.Warn("save federation hash failed", "err", retErr.Error(), "coinType", m.coinType)
		return false
	}

	return true
}

func (m *MortgageWatcher) processConfirmBlock(blockData *coinmanager.BlockData) {
	for _, tx := range blockData.MsgBolck.Transactions {
		txHash := tx.TxHash().String()

		hasReturn := false
		isFedAddr := false
		isFromFedAddr := false
		var value int64
		var message *Message
		var err error

		//update utxo status

		for _, vin := range tx.TxIn {
			utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
			utxoInfo := m.GetUtxoInfoByID(utxoID)
			if utxoInfo != nil {
				isFromFedAddr = true
			}

		}

		if isFromFedAddr {
			m.storeHashMapping(tx)
		}

		for voutIndex, vout := range tx.TxOut {
			address := coinmanager.ExtractPkScriptAddr(vout.PkScript, m.coinType)
			if address != "" {
				if _, ok := m.federationMap.Load(address); ok {
					isFedAddr = true
					value = vout.Value
					id := strings.Join([]string{txHash, strconv.Itoa(voutIndex)}, "_")
					log.Debug("FIND NEW UTXO", "id", id, "value", value, "coinType", m.coinType)
				}
			} else {
				message, err = ParserPayLoadScript(vout.PkScript)
				if err == nil {
					hasReturn = true
				}
			}
		}

		// make mortgage tx
		if isFedAddr && hasReturn {
			mortgageTx := SubTransaction{
				ScTxid:    tx.TxHash().String(),
				Amount:    value,
				From:      m.coinType,
				To:        message.ChainName,
				TokenFrom: 0,
				TokenTo:   message.APPNumber,
				RechargeList: []*AddressInfo{
					{
						Address: message.Address,
						Amount:  value,
					},
				},
			}

			log.Debug("push mortgage tx", "tx", mortgageTx, "coinType", m.coinType)
			m.mortgageTxChan <- &mortgageTx
		}
	}

}

func (m *MortgageWatcher) processNewTx(newTx *wire.MsgTx) {
	txHash := newTx.TxHash().String()
	//update utxo status
	isFromFedAddr := false

	for _, vin := range newTx.TxIn {
		utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
		utxoInfo := m.GetUtxoInfoByID(utxoID)
		if utxoInfo != nil {
			isFromFedAddr = true
		}
	}

	if isFromFedAddr {
		log.Info("process tx", "tx_hash", txHash, "coinType", m.coinType)
		m.storeHashMapping(newTx)
	}
}

func (m *MortgageWatcher) processNewUnconfirmBlock(blockData *coinmanager.BlockData) {
	for _, tx := range blockData.MsgBolck.Transactions {
		m.processNewTx(tx)
	}
}

//StartWatch 启动监听已确认和未确认的区块以及新交易，提取抵押交易
func (m *MortgageWatcher) StartWatch() {
	m.utxoMonitor()
	m.syncUtxoInfo()

	m.bwClient.WatchNewTxFromNodeMempool()
	m.bwClient.WatchNewBlock()

	confirmBlockChan := m.bwClient.GetConfirmChan()
	newTxChan := m.bwClient.GetNewTxChan()
	newUnconfirmBlockChan := m.bwClient.GetNewUnconfirmBlockChan()

	go func() {
		for {
			select {
			case newConfirmBlock := <-confirmBlockChan:
				log.Info("process confirm block height:", "height", newConfirmBlock.BlockInfo.Height, "coinType", m.coinType)
				m.processConfirmBlock(newConfirmBlock)
				m.scanConfirmHeight = newConfirmBlock.BlockInfo.Height + 1

				height := strconv.Itoa(int(m.scanConfirmHeight))
				err := m.levelDb.Put([]byte(confirmHeightLDKey), []byte(height))
				if err != nil {
					log.Error("Save confirmHeight Failed", "err", err.Error(), "height", height)
				}

			case newTx := <-newTxChan:
				m.processNewTx(newTx)
			case newUnconfirmBlock := <-newUnconfirmBlockChan:
				log.Info("process new block height:", "height", newUnconfirmBlock.BlockInfo.Height, "coinType", m.coinType)
				m.processNewUnconfirmBlock(newUnconfirmBlock)
			}
		}
	}()

}
