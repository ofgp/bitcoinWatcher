package coinmanager

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/ofgp/bitcoinWatcher/util"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/cpacia/bchutil"
	log "github.com/inconshreveable/log15"
	"github.com/spf13/viper"
)

const (
	sigHashForkID txscript.SigHashType = 0x40
	sigHashMask                        = 0x1f
)

func init() {
	viper.SetDefault("net_param", "mainnet")
}

func getNetParams() *chaincfg.Params {
	switch viper.GetString("net_param") {
	case "mainnet":
		return &chaincfg.MainNetParams
	case "testnet":
		return &chaincfg.TestNet3Params
	case "regtest":
		return &chaincfg.RegressionNetParams
	default:
		return nil
	}

}

//ExtractPkScriptAddr 从输出脚本中提取地址
func ExtractPkScriptAddr(PkScript []byte, coinType string) string {
	scriptClass, addresses, _, err := txscript.ExtractPkScriptAddrs(
		PkScript, getNetParams())

	if err != nil {
		log.Warn("ExtractPkScriptAddrs:", "err", err.Error())
		return ""
	}

	if scriptClass == txscript.NullDataTy {
		return ""
	}

	if len(addresses) > 0 {
		//address := addresses[0].EncodeAddress()

		var addressList []string
		for _, addr := range addresses {
			//log.Debug("addr type", "addr type", reflect.TypeOf(addr).String())
			if coinType == "btc" {
				addressList = append(addressList, addr.EncodeAddress())
			} else {
				switch reflect.TypeOf(addr).String() {
				case "*btcutil.AddressPubKey":
					addr2, err := bchutil.NewCashAddressPubKeyHash(btcutil.Hash160(addr.ScriptAddress()), getNetParams())
					if err != nil {
						log.Warn("NewCashAddressPubKeyHash failed:", "err", err.Error())
						return ""
					}
					addressList = append(addressList, addr2.String())
				case "*btcutil.AddressPubKeyHash":
					addr2, err := bchutil.NewCashAddressPubKeyHash(addr.ScriptAddress(), getNetParams())
					if err != nil {
						log.Warn("NewCashAddressPubKeyHash failed:", "err", err.Error())
						return ""
					}
					addressList = append(addressList, addr2.String())
				case "*btcutil.AddressScriptHash":
					addr2, err := bchutil.NewCashAddressScriptHashFromHash(addr.ScriptAddress(), getNetParams())
					if err != nil {
						log.Warn("NewCashAddressScriptHashFromHash failed:", "err", err.Error())
						return ""
					}
					addressList = append(addressList, addr2.String())
				}
			}

		}
		return strings.Join(addressList, "|")

		/*
			switch scriptClass {
			case txscript.PubKeyTy:
				addr2, err := bchutil.NewCashAddressPubKeyHash(btcutil.Hash160(addresses[0].ScriptAddress()), getNetParams())
				if err != nil {
					log.Warn("NewCashAddressPubKeyHash failed:", "err", err.Error())
					return ""
				}
				return addr2.String()
			case txscript.PubKeyHashTy:
				addr2, err := bchutil.NewCashAddressPubKeyHash(addresses[0].ScriptAddress(), getNetParams())
				if err != nil {
					log.Warn("NewCashAddressPubKeyHash failed:", "err", err.Error())
					return ""
				}
				return addr2.String()
			case txscript.ScriptHashTy:
				addr2, err := bchutil.NewCashAddressScriptHashFromHash(addresses[0].ScriptAddress(), getNetParams())
				if err != nil {
					log.Warn("NewCashAddressScriptHashFromHash failed:", "err", err.Error())
					return ""
				}
				return addr2.String()
			}*/
	}

	return ""
}

//ExtractPkScriptMessage 从脚本中提取message
func ExtractPkScriptMessage(PkScript []byte) string {
	scriptClass, _, _, err := txscript.ExtractPkScriptAddrs(
		PkScript, getNetParams())

	if err != nil {
		log.Warn("ExtractPkScriptAddrs:", "err", err.Error())
		return ""
	}

	if scriptClass == txscript.NullDataTy {
		return string(PkScript[2:])
	}
	return ""
}

//GetMultiSigAddress 通过公钥列表生成多签地址
func GetMultiSigAddress(addressPubkeyList []string, nrequired int, coinType string) (string, []byte, error) {
	var pubkey []*btcutil.AddressPubKey
	var script []byte
	for _, tempString := range addressPubkeyList {
		tempHex, err := hex.DecodeString(tempString)
		if err != nil {
			return "", script, err
		}
		tempAddr, err := btcutil.NewAddressPubKey(tempHex, getNetParams())
		if err != nil {
			return "", script, err
		}
		pubkey = append(pubkey, tempAddr)
	}

	script, err := txscript.MultiSigScript(pubkey, nrequired)
	if err != nil {
		return "", script, err
	}

	switch coinType {
	case "btc":
		scriptAddr, err := btcutil.NewAddressScriptHash(script, getNetParams())
		if err != nil {
			return "", script, err
		}

		return scriptAddr.EncodeAddress(), script, err
	case "bch":
		scriptAddr, err := bchutil.NewCashAddressScriptHashFromHash(btcutil.Hash160(script), getNetParams())
		if err != nil {
			log.Error("make cash address err", "err", err.Error())
			return "", script, err
		}
		return scriptAddr.EncodeAddress(), script, err
	}

	return "", script, err

}

//CalcBip143SignatureHash 根据交易数据计算待签名的hash
func CalcBip143SignatureHash(subScript []byte, sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType, tx *wire.MsgTx, idx int, amt int64) []byte {

	if idx > len(tx.TxIn)-1 {
		fmt.Printf("calcBip143SignatureHash error: idx %d but %d txins",
			idx, len(tx.TxIn))
		return nil
	}

	var sigHash bytes.Buffer

	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version))
	sigHash.Write(bVersion[:])

	var zeroHash chainhash.Hash

	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(sigHashes.HashPrevOuts[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashSequence[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
	var bIndex [4]byte
	binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
	sigHash.Write(bIndex[:])

	wire.WriteVarBytes(&sigHash, 0, subScript)

	var bAmount [8]byte
	binary.LittleEndian.PutUint64(bAmount[:], uint64(amt))
	sigHash.Write(bAmount[:])
	var bSequence [4]byte
	binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
	sigHash.Write(bSequence[:])

	if hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashOutputs[:])
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var b bytes.Buffer
		wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx])
		sigHash.Write(chainhash.DoubleHashB(b.Bytes()))
	} else {
		sigHash.Write(zeroHash[:])
	}

	var bLockTime [4]byte
	binary.LittleEndian.PutUint32(bLockTime[:], tx.LockTime)
	sigHash.Write(bLockTime[:])
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType|sigHashForkID))
	sigHash.Write(bHashType[:])

	return chainhash.DoubleHashB(sigHash.Bytes())
}

//RawTxInSignature 对交易进行签名
func RawTxInSignature(tx *wire.MsgTx, idx int, subScript []byte, hashType txscript.SigHashType,
	value int64, coinType string,
	nodePubKeyHash string) ([]byte, error) {

	var hash []byte

	if coinType == "bch" {
		hash = CalcBip143SignatureHash(subScript, txscript.NewTxSigHashes(tx), hashType, tx, idx, value)
	} else {
		hash, _ = txscript.CalcSignatureHash(subScript, hashType, tx, idx)
	}

	signature, err := util.Sign(hex.EncodeToString(hash), nodePubKeyHash)

	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}
	signatureDerHex, _ := hex.DecodeString(signature.SignatureDerHex)

	if coinType == "bch" {
		return append(signatureDerHex, byte(hashType|sigHashForkID)), nil
	}

	return append(signatureDerHex, byte(hashType)), nil
}

//DecodeAddress 从地址字符串中decode Address
func DecodeAddress(addr string, coinType string) (btcutil.Address, error) {
	switch coinType {
	case "btc":
		return btcutil.DecodeAddress(addr, getNetParams())
	case "bch":
		return bchutil.DecodeAddress(addr, getNetParams())
	default:
		return nil, nil
	}

}

//CheckIsCoinBase 检查是否是coinbase hash
func CheckIsCoinBase(hash string) bool {
	if hash == "0000000000000000000000000000000000000000000000000000000000000000" {
		return true
	}
	return false
}

//NewPrivateKey 生成私钥与公钥
func NewPrivateKey() ([]byte, []byte) {
	key, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, nil
	}

	pk := (*btcec.PublicKey)(&key.PublicKey).
		SerializeCompressed()

	return key.Serialize(), pk
}

//CoinSelect utxo coin选择算法
func CoinSelect(utxoList []*UtxoInfo, targetValue int64, confirmHeight int64) ([]*UtxoInfo, int64) {
	sorter := &UtxoSorter{
		UtxoList:       utxoList,
		MaxBlockHeight: confirmHeight,
	}

	//已确认的在前，未确认的在后
	//确认数>6的在前，确认数=6的在后
	//金额小的在前，大的在后
	sort.Sort(sorter)

	var retCoin []*UtxoInfo
	var coinValueSum int64

	var lowerCoin []*UtxoInfo
	var lowerSum int64

	var coinLowestLarger *UtxoInfo
	var coinLowestLargerValue int64 = -1

	//优先挑金额与目标金额相等的utxo
	for _, utxoInfo := range sorter.UtxoList {
		if utxoInfo.Value == targetValue {
			retCoin = append(retCoin, utxoInfo)
			coinValueSum += utxoInfo.Value
			return retCoin, coinValueSum
		} else if utxoInfo.Value < targetValue {
			lowerCoin = append(lowerCoin, utxoInfo)
			lowerSum += utxoInfo.Value
		} else if utxoInfo.Value < coinLowestLargerValue || coinLowestLargerValue == -1 {
			coinLowestLarger = utxoInfo
			coinLowestLargerValue = utxoInfo.Value
		}
	}

	//优先挑金额大于目标值中的最小值
	if coinLowestLargerValue != -1 {
		retCoin = append(retCoin, coinLowestLarger)
		coinValueSum += coinLowestLarger.Value

		if len(lowerCoin) > 0 && lowerCoin[0].Value > 0 && coinLowestLarger.Value/lowerCoin[0].Value >= 10 {
			retCoin = append(retCoin, lowerCoin[0])
			coinValueSum += lowerCoin[0].Value
		}

		return retCoin, coinValueSum
	}

	if lowerSum < targetValue {
		return retCoin, coinValueSum
	}

	//从小于集合中，优先挑选旧的已确认的utxo，次选新的utxo
	i := 0
	freshUtxoIndex := len(lowerCoin) - 1
	for freshUtxoIndex >= 0 {
		if lowerCoin[freshUtxoIndex].SpendType == 1 && confirmHeight-lowerCoin[freshUtxoIndex].BlockHeight > 0 {
			break
		}
		freshUtxoIndex--
	}

	j := freshUtxoIndex
	//log.Debug("freshUtxoIndex", "freshUtxoIndex", j)

	for i <= j {
		coinValueSum += lowerCoin[j].Value
		retCoin = append(retCoin, lowerCoin[j])
		if coinValueSum >= targetValue {
			break
		}

		if j == i {
			break
		}

		coinValueSum += lowerCoin[i].Value
		retCoin = append(retCoin, lowerCoin[i])
		if coinValueSum >= targetValue {
			break
		}

		i++
		j--
	}

	for j := freshUtxoIndex + 1; j < len(lowerCoin); j++ {
		if coinValueSum >= targetValue {
			break
		}
		coinValueSum += lowerCoin[j].Value
		retCoin = append(retCoin, lowerCoin[j])
	}

	return retCoin, coinValueSum

	/*
		if lowerSum == targetValue {
			return lowerCoin, lowerSum
		}

		if lowerSum < targetValue {
			if coinLowestLargerValue == -1 {
				return retCoin, coinValueSum
			}

			retCoin = append(retCoin, coinLowestLarger)
			coinValueSum += coinLowestLarger.Value
			return retCoin, coinValueSum
		}

		nBest := lowerSum
		vBest := make([]int, len(lowerCoin))
		for i := range vBest {
			vBest[i] = 1
		}

		log.Debug("lowerCoin", "len", len(lowerCoin), "lowerSum", lowerSum)

		for rep := 0; rep < 100 && nBest != targetValue; rep++ {
			var nTotal int64
			vInclude := make([]int, len(lowerCoin))

			for id, utxoInfo := range lowerCoin {
				rand.Seed(time.Now().UnixNano())
				if rand.Intn(100)%2 == 0 {
					nTotal += utxoInfo.Value
					vInclude[id] = 1

					if nTotal >= targetValue {
						if nTotal <= nBest {
							nBest = nTotal
							copy(vBest, vInclude)
							break
						}
						nTotal -= utxoInfo.Value
						vInclude[id] = 0
					}
				}
			}
		}

		if coinLowestLargerValue != -1 && coinLowestLargerValue-targetValue <= nBest-targetValue {
			retCoin = append(retCoin, coinLowestLarger)
			coinValueSum += coinLowestLarger.Value
			return retCoin, coinValueSum
		}

		for id, utxoInfo := range lowerCoin {
			if vBest[id] == 1 {
				retCoin = append(retCoin, utxoInfo)
			}
		}
		return retCoin, nBest
	*/

}
