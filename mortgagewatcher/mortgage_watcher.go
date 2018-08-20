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

	"github.com/ofgp/bitcoinWatcher/coinmanager"
	"github.com/ofgp/bitcoinWatcher/dbop"
	"github.com/ofgp/bitcoinWatcher/util"

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
)

func init() {
	homeDir, _ := util.GetHomeDir()
	dbPath := path.Join(homeDir, "btc_db")
	viper.SetDefault("LEVELDB.btc_db_path", dbPath)
	dbPath = path.Join(homeDir, "bch_db")
	viper.SetDefault("LEVELDB.bch_db_path", dbPath)

}

//UtxoCacheMap utxoCache缓存
type UtxoCacheMap struct {
	sync.Mutex
	CacheUtxo map[string]*coinmanager.UtxoInfo
}

//NewUtxoCacheMap 新建一个utxoCache
func NewUtxoCacheMap() *UtxoCacheMap {
	return &UtxoCacheMap{
		CacheUtxo: make(map[string]*coinmanager.UtxoInfo),
	}
}

//Get 从缓存中查询一个utxo信息，没有则返回nil
func (ucm *UtxoCacheMap) Get(id string) *coinmanager.UtxoInfo {
	ucm.Lock()
	defer ucm.Unlock()

	if _, ok := ucm.CacheUtxo[id]; ok {
		return ucm.CacheUtxo[id]
	}
	return nil
}

//Set 储存一个utxo信息
func (ucm *UtxoCacheMap) Set(id string, utxo *coinmanager.UtxoInfo) {
	ucm.Lock()
	defer ucm.Unlock()

	ucm.CacheUtxo[id] = utxo

}

//Delete 从缓存中删除一个utxo
func (ucm *UtxoCacheMap) Delete(id string) {
	ucm.Lock()
	defer ucm.Unlock()
	delete(ucm.CacheUtxo, id)
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
	faUtxoInfo        sync.Map
	levelDb           *dbop.LDBDatabase
	utxoMonitorCount  map[string]int
	levelDbUtxoPreFix string
	levelDbTxPreFix   string
	federationMap     sync.Map
	timeout           int
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
		utxoMonitorCount:  make(map[string]int),
		timeout:           timeout,
	}

	mw.federationMap.Store(federationAddress, redeemScript)

	mw.levelDbUtxoPreFix = strings.Join([]string{coinType, "utxo"}, "_")
	mw.levelDbTxPreFix = strings.Join([]string{coinType, "hash_mapping"}, "_")

	iter := levelDb.NewIteratorWithPrefix([]byte(mw.levelDbUtxoPreFix))
	for iter.Next() {
		utxo := &coinmanager.UtxoInfo{}
		err := json.Unmarshal(iter.Value(), utxo)
		if err != nil {
			log.Warn("Unmarshal UTXO FROM LEVELDB ERR", "err", err.Error(), "coinType", coinType)
			continue
		}

		if utxo.SpendType == 3 {
			continue
		}
		mw.faUtxoInfo.Store(string(iter.Key())[9:], utxo)
		//log.Debug("utxo info", "id", string(iter.Key())[9:], "utxo", utxo, "coinType", coinType)
	}

	return &mw, err
}

func (m *MortgageWatcher) utxoMonitor() {
	go func() {
		for {
			m.faUtxoInfo.Range(func(k, v interface{}) bool {
				utxoID := k.(string)
				utxoInfo := v.(*coinmanager.UtxoInfo)

				if utxoInfo.SpendType == 4 {
					if _, ok := m.utxoMonitorCount[utxoID]; !ok {
						m.utxoMonitorCount[utxoID] = 0
					}
					m.utxoMonitorCount[utxoID]++

					//utxo临时占用超时，状态改回未使用
					if m.utxoMonitorCount[utxoID] >= m.timeout {
						utxoInfo.SpendType = 1
						m.storeUtxo(utxoID)
						delete(m.utxoMonitorCount, utxoID)
					}

				} else {
					if _, ok := m.utxoMonitorCount[utxoID]; ok {
						delete(m.utxoMonitorCount, utxoID)
					}
				}

				return true
			})

			time.Sleep(time.Duration(1) * time.Second)
		}
	}()
}

func (m *MortgageWatcher) storeUtxo(utxoID string) bool {
	t, ok := m.faUtxoInfo.Load(utxoID)
	if ok {
		utxoInfo := t.(*coinmanager.UtxoInfo)
		data, err := json.Marshal(utxoInfo)
		if err != nil {
			log.Warn("Marshal utxo failed", "err", err.Error(), "coinType", m.coinType)
			return false
		}

		key := strings.Join([]string{m.levelDbUtxoPreFix, utxoID}, "_")

		retErr := m.levelDb.Put([]byte(key), []byte(data))
		if retErr != nil {
			log.Warn("Marshal utxo failed", "err", err.Error(), "coinType", m.coinType)
			return false
		}

		return true
	}

	return false
}

//GetBlockNumber 获取当前已监听到的区块
func (m *MortgageWatcher) GetBlockNumber() int64 {
	return m.scanConfirmHeight
}

//GetFederationAddress 获取联盟多签地址
func (m *MortgageWatcher) GetFederationAddress() string {
	return m.federationAddress
}

//GetUnspentUtxo 获得指定地址未花费的utxo
func (m *MortgageWatcher) GetUnspentUtxo(address string) []*coinmanager.UtxoInfo {
	var retList []*coinmanager.UtxoInfo
	var sum int64

	m.faUtxoInfo.Range(func(k, v interface{}) bool {
		utxoInfo := v.(*coinmanager.UtxoInfo)
		if utxoInfo.SpendType == 1 && utxoInfo.Address == address {
			retList = append(retList, utxoInfo)
			sum += utxoInfo.Value
		}
		return true
	})

	log.Debug("Unspent Utxo value", "sum", sum)
	return retList
}

//ChangeFederationAddress 修改多签地址
func (m *MortgageWatcher) ChangeFederationAddress(federationAddress string, redeemScript []byte) {
	m.Lock()
	defer m.Unlock()
	m.federationAddress = federationAddress
	m.redeemScript = redeemScript
	m.federationMap.Store(federationAddress, redeemScript)
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
		hash, err := chainhash.NewHashFromStr(selectCoin.VoutTxid)
		if err != nil {
			log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", hash, "coinType", m.coinType)
			return nil
		}

		selectCoin.SpendType = 4
		utxoID := strings.Join([]string{selectCoin.VoutTxid, strconv.Itoa(int(selectCoin.VoutIndex))}, "_")
		log.Debug("select coin", "utxo_id", utxoID, "coinType", m.coinType)
		m.storeUtxo(utxoID)

		vin := wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: selectCoin.VoutIndex,
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
	feePerKB, err := bitcoinClient.EstimateFee(1)
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
//功能：根据提币地址和提币金额、矿工费，拉取联盟地址可用UTXO创建提币交易数据
//输入： addrList： 提币地址与金额
//		fee 矿工费
//输出： 交易数据
func (m *MortgageWatcher) CreateCoinTx(addrList []*AddressInfo, fee int64, ScTxid string) (*wire.MsgTx, int) {
	m.Lock()
	defer m.Unlock()

	var totalValue int64

	for _, addrInfo := range addrList {
		totalValue += addrInfo.Amount
	}

	//TODO: total_value是否要按一定比例收取手续费

	unspentUtxoList := m.GetUnspentUtxo(m.federationAddress)
	log.Debug("utxolist", "len", len(unspentUtxoList))

	selectCoinList, coinSum := coinmanager.CoinSelect(unspentUtxoList, totalValue+fee, m.scanConfirmHeight)

	log.Debug("selectCoinList", "len", len(selectCoinList), "coinSum", coinSum)

	if coinSum < totalValue+fee {
		log.Warn("COIN NOT ENOUGH", "coinType", m.coinType)
		return nil, 1
	}

	//TODO: miner fee
	if coinSum > totalValue+fee {
		smallChange := AddressInfo{
			Address: m.federationAddress,
			Amount:  coinSum - totalValue - fee,
		}
		addrList = append(addrList, &smallChange)
	}

	tx := wire.NewMsgTx(1)

	//new vin
	for _, selectCoin := range selectCoinList {
		hash, err := chainhash.NewHashFromStr(selectCoin.VoutTxid)
		if err != nil {
			log.Warn("NEW_HASH_FAILED:", "err", err.Error(), "hash", hash, "coinType", m.coinType)
			return nil, 100
		}

		selectCoin.SpendType = 4
		utxoID := strings.Join([]string{selectCoin.VoutTxid, strconv.Itoa(int(selectCoin.VoutIndex))}, "_")
		log.Debug("select coin", "utxo_id", utxoID, "coinType", m.coinType)
		m.storeUtxo(utxoID)

		vin := wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: selectCoin.VoutIndex,
			},
		}

		tx.AddTxIn(&vin)

	}

	//new vout
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

	if ScTxid != "" {
		pkScript1, err := txscript.NullDataScript([]byte(ScTxid))
		if err != nil {
			return nil, 2
		}

		vout1 := wire.TxOut{
			Value:    0,
			PkScript: pkScript1,
		}
		tx.AddTxOut(&vout1)
	}

	return tx, 0

}

//SignTx 对交易数据签名，返回交易签名
func (m *MortgageWatcher) SignTx(tx *wire.MsgTx, nodePubKeyHash string) ([][]byte, int) {

	var sigs [][]byte

	for i, vin := range tx.TxIn {
		utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
		t, ok := m.faUtxoInfo.Load(utxoID)
		if ok {
			utxoInfo := t.(*coinmanager.UtxoInfo)
			rs, rsok := m.federationMap.Load(utxoInfo.Address)
			if rsok {
				if utxoInfo.SpendType == 2 {
					log.Warn("Utxo using", "utxoID", utxoID)
					return sigs, 4
				}

				utxoInfo.SpendType = 4
				m.storeUtxo(utxoID)

				redeemScript := rs.([]byte)
				sig, err := coinmanager.RawTxInSignature(tx, i, redeemScript, txscript.SigHashAll,
					utxoInfo.Value, m.coinType, nodePubKeyHash,
				)
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
		t, ok := m.faUtxoInfo.Load(utxoID)
		if !ok {
			log.Warn("【MergeSignTx】CAN'T FIND UTXO", "utxo", utxoID)
			return false
		}

		utxoInfo := t.(*coinmanager.UtxoInfo)
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
		t, ok := m.faUtxoInfo.Load(utxoID)
		if ok {
			utxoInfo := t.(*coinmanager.UtxoInfo)
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

func (m *MortgageWatcher) TxTest() {
	addrList := []*AddressInfo{
		{
			Address: "bchreg:qzj7sr407etdfaletclgn7ut3nl3hxxqusfeje0vmf",
			Amount:  500000,
		},
	}

	tx, _ := m.CreateCoinTx(addrList, 10000, "")
	log.Debug("tx hash", "tx hash", tx.TxHash().String())

	pubKey1, _ := hex.DecodeString("049FD6230E3BADBBC7BA190E10B2FC5C3D8EA9B758A43E98AB2C8F83C826AE7EABEA6D88880BC606FA595CD8DD17FC7784B3E55D8EE0705045119545A803215B80")

	pubKey2, _ := hex.DecodeString("044667E5B36F387C4D8D955C33FC271F46D791FD3433C0B2F517375BBD9AAE6B8C2392229537B109AC8EADCCE104AEAA64DB2D90BEF9008A09F8563CDB05FFB60B")

	pubKey3, _ := hex.DecodeString("04A2E82BE35D90D954E15CC5865E2F8AC22FD2DDBD4750F4BFC7596363A3451D1B75F4A8BAD28CF48F63595349DBC141D6D6E21F4FEB65BDC5E1A8382A2775E787")

	var sigsList [][][]byte
	sigs1, _ := m.SignTx(tx, "E37B5BEBF46B6CAA4B2146CCD83D61966B33687A")
	log.Debug("sigs1 verify", "verify result", m.VerifySign(tx, sigs1, pubKey1))

	sigs2, _ := m.SignTx(tx, "BA3F9DF40CC2DD39D36A814865982110F84CAAD3")
	log.Debug("sigs2 verify", "verify result", m.VerifySign(tx, sigs2, pubKey2))

	sigs3, _ := m.SignTx(tx, "3722834BCB13F7308C28907B69A99DB462F39036")
	log.Debug("sigs3 verify", "verify result", m.VerifySign(tx, sigs3, pubKey3))

	sigsList = append(sigsList, sigs1)
	sigsList = append(sigsList, sigs2)
	sigsList = append(sigsList, sigs3)

	m.MergeSignTx(tx, sigsList)
	log.Debug("tx hash", "tx hash", tx.TxHash().String())

	log.Debug("sigs:", "sig", hex.EncodeToString(tx.TxIn[0].SignatureScript))

	hash, err := m.SendTx(tx)
	if err != nil {
		log.Debug("SendTx err", "err", err.Error())
		return
	}
	log.Debug("Send Tx", "HASH", hash)

}

//GetTxByHash 通过交易hash从链上查询交易数据，查询提币交易通过签名前的交易HASH来查询（以保障各节点可独立验证，不依赖主节点发送的交易HASH）
//查询抵押交易使用链上的交易HASH查询。
func (m *MortgageWatcher) GetTxByHash(hash string) *Transaction {
	key := strings.Join([]string{m.levelDbTxPreFix, hash}, "_")

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
	key := strings.Join([]string{m.levelDbTxPreFix, hashBeforeSign}, "_")
	log.Debug("storeHashMap", "hash_before_sign", hashBeforeSign, "hash_after_sign", hashAfterSign, "coinType", m.coinType)

	retErr := m.levelDb.Put([]byte(key), []byte(hashAfterSign))
	if retErr != nil {
		log.Warn("Marshal utxo failed", "err", retErr.Error(), "coinType", m.coinType)
		return false
	}

	return true

}

//GetUtxoInfoByID 通过ID查询utxo信息
func (m *MortgageWatcher) GetUtxoInfoByID(utxoID string) *coinmanager.UtxoInfo {
	t, ok := m.faUtxoInfo.Load(utxoID)
	if ok {
		utxoInfo := t.(*coinmanager.UtxoInfo)
		return utxoInfo
	}
	return nil
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
			t, ok := m.faUtxoInfo.Load(utxoID)
			if ok {
				utxoInfo := t.(*coinmanager.UtxoInfo)
				utxoInfo.SpendType = 3
				utxoInfo.VinTxid = tx.TxHash().String()
				m.storeUtxo(utxoID)
				isFromFedAddr = true
				m.faUtxoInfo.Delete(utxoID)
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

					t, ok := m.faUtxoInfo.Load(id)
					if !ok {
						newUtxo := coinmanager.UtxoInfo{
							Address:      address,
							VoutTxid:     txHash,
							VoutIndex:    uint32(voutIndex),
							Value:        vout.Value,
							VoutPkscript: hex.EncodeToString(vout.PkScript),
							SpendType:    1,
							BlockHeight:  blockData.BlockInfo.Height,
						}
						m.faUtxoInfo.Store(id, &newUtxo)
					} else {
						utxoInfo := t.(*coinmanager.UtxoInfo)
						if utxoInfo.SpendType < 1 {
							utxoInfo.SpendType = 1
						}
					}
					m.storeUtxo(id)

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
		t, ok := m.faUtxoInfo.Load(utxoID)
		if ok {
			utxoInfo := t.(*coinmanager.UtxoInfo)
			utxoInfo.SpendType = 2
			utxoInfo.VinTxid = newTx.TxHash().String()
			m.storeUtxo(utxoID)
			isFromFedAddr = true
		}
	}

	for voutIndex, vout := range newTx.TxOut {
		address := coinmanager.ExtractPkScriptAddr(vout.PkScript, m.coinType)
		if address != "" {
			if _, ok := m.federationMap.Load(address); ok {

				if isFromFedAddr {
					spendType := 0

					id := strings.Join([]string{txHash, strconv.Itoa(voutIndex)}, "_")
					newUtxo := coinmanager.UtxoInfo{
						Address:      address,
						VoutTxid:     txHash,
						VoutIndex:    uint32(voutIndex),
						Value:        vout.Value,
						VoutPkscript: hex.EncodeToString(vout.PkScript),
						SpendType:    int32(spendType),
					}

					_, ok := m.faUtxoInfo.Load(id)
					if !ok {
						m.faUtxoInfo.Store(id, &newUtxo)
						m.storeUtxo(id)
					}
				}

			}
		}
	}

	if isFromFedAddr {
		log.Info("process tx", "tx_hash", txHash, "coinType", m.coinType)
		m.storeHashMapping(newTx)
	}
}

func (m *MortgageWatcher) processNewUnconfirmBlock(blockData *coinmanager.BlockData) {
	for _, tx := range blockData.MsgBolck.Transactions {
		txHash := tx.TxHash().String()

		//update utxo status
		isFromFedAddr := false
		for _, vin := range tx.TxIn {
			utxoID := strings.Join([]string{vin.PreviousOutPoint.Hash.String(), strconv.Itoa(int(vin.PreviousOutPoint.Index))}, "_")
			t, ok := m.faUtxoInfo.Load(utxoID)
			if ok {
				utxoInfo := t.(*coinmanager.UtxoInfo)
				utxoInfo.SpendType = 2
				utxoInfo.VinTxid = tx.TxHash().String()
				m.storeUtxo(utxoID)
				isFromFedAddr = true
			}
		}

		for voutIndex, vout := range tx.TxOut {
			address := coinmanager.ExtractPkScriptAddr(vout.PkScript, m.coinType)
			if address != "" {
				if _, ok := m.federationMap.Load(address); ok {
					if isFromFedAddr {
						spendType := 0

						id := strings.Join([]string{txHash, strconv.Itoa(voutIndex)}, "_")
						newUtxo := coinmanager.UtxoInfo{
							Address:      address,
							VoutTxid:     txHash,
							VoutIndex:    uint32(voutIndex),
							Value:        vout.Value,
							VoutPkscript: hex.EncodeToString(vout.PkScript),
							SpendType:    int32(spendType),
							BlockHeight:  blockData.BlockInfo.Height,
						}

						t, ok := m.faUtxoInfo.Load(id)
						if !ok {
							m.faUtxoInfo.Store(id, &newUtxo)
						} else {
							utxoInfo := t.(*coinmanager.UtxoInfo)
							utxoInfo.BlockHeight = blockData.BlockInfo.Height
						}
						m.storeUtxo(id)

					}

					//log.Debug("FIND NEW UTXO", "id", id, "value", newUtxo.Value, "coinType", m.coinType)

				}
			}
		}

		if isFromFedAddr {
			m.storeHashMapping(tx)
		}
	}
}

//StartWatch 启动监听已确认和未确认的区块以及新交易，提取抵押交易
func (m *MortgageWatcher) StartWatch() {
	m.utxoMonitor()
	m.bwClient.WatchConfirmBlock()
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
