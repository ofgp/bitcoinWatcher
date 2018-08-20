#MortgageWatcher

抵押交易监听类，通过监听BTC/BCH主链上达到确认数的区块，从中解析出抵押到网关联盟地址的交易，通过chan推送给网关节点。 同时提供交易创建、签名、发送的接口用于完成提币操作。

抵押交易：user地址发送一笔金额到网关联盟地址，并在交易中附上要在侧链上铸币的信息

提币交易：user在侧链熔币后，将金额提币到主链地址

##接口说明

###NewMortgageWatcher

	功能：创建一个抵押交易监听实例
	输入：
	1. coinType string： btc/bch， 选择要监听的币种类型
	2. confirmHeight int64： 监听开始的高度
	3. federationAddress string：联盟多签地址
	4. redeemScript []byte: 联盟多签地址兑现脚本
	输出：
	MortgageWatcher实例

###StartWatch

	功能：启动监听已确认和未确认的区块以及新交易，从中提取抵押交易，更新联盟多签地址的UTXO状态
	
###GetTxChan

	功能：获取抵押交易的chan，用于从中获得抵押交易数据
	
###GetTxByHash

	功能：通过交易hash从链上查询交易数据，查询提币交易通过签名前的交易HASH来查询（以保障各节点可独立验证，不依赖主节点发送的交易HASH),查询抵押交易使用链上的交易HASH查询
	输入：
	1. hash string: 交易hash
	输出：
	交易对象， 如果nil表示交易未查询到
	
###SendTx

	功能：将交易发送到链上
	输入：
	1.tx *wire.MsgTx， 已签名的交易数据
	
	输出：
	1. hash string: 交易hash
	2. err error: 不为空则表示发送出错

###VerifySign

	功能：判断一个签名是否与对应公钥匹配
	输入：
	1. tx *wire.MsgTx： 交易数据
	2. sigs [][]byte: 签名数据
	3. pubKey []byte： 公钥数据
	
	输出：
	bool: 是否匹配


###MergeSignTx

	功能：合并多组节点对某笔交易的签名
	
	输入：
	1. tx *wire.MsgTx： 交易数据
	2. sigsList [][][]byte： 多组签名数据
	输出：
	bool: 合并是否成功


###SignTx

	功能：使用密钥签名服务，对交易数据签名，返回交易签名
	输入：
	1. tx *wire.MsgTx：待签交易数据 
	2. nodePubKeyHash string： 签名服务公钥

	输出：
	签名

###CreateCoinTx

	功能：根据提币地址和提币金额、矿工费，拉取联盟地址可用UTXO创建提币交易数据
	输入： 
	1. addrList： 提币地址与金额
	2. fee 矿工费
	输出： 
	交易数据
	
#BitCoinWatcher

btc/bch监听类，用于监听区块链上已确认的区块、新区块、内存中的新交易

##接口说明

###WatchConfirmBlock

	功能：
	启动线程监听已达到确认数的区块，push进chan

###GetConfirmChan

	功能：
	获取已确认区块chan
	返回：chan对象
	
###WatchNewBlock

	功能：
	启动线程监听新区块，push进chan
	

###GetNewUnconfirmBlockChan

	功能：获取新未确认区块CHAN
	返回：chan对象

###WatchNewTxFromNodeMempool

	功能：启动监听全节点内存中的新交易

###GetNewTxChan

	功能：获取交易CHAN
	返回：chan对象
	
#BitCoinClient

btc/bch rpc客户端，用于连接全节点进行rpc接口调用

##接口说明

###NewBitCoinClient

	功能：创建一个bitcoin操作客户端
	输入：
	1. coinType： btc/bch
	输出：
	bitcoin rpc客户端
	
###CheckIsConfirm

	功能：检查区块是否已确认
	输入：
	1. blockData *BlockData： 区块对象
	输出：
	bool
	
###CheckTxIsConfirm

	功能：检查交易是否已确认
	输入：
	1. txHash string： 交易hash
	输出：
	bool
	

###GetBlockCount

	功能： 获取当前区块链高度
	输出：
	区块链高度


###GetRawTransaction

	功能：根据txhash从区块链上查询交易数据
	输入：
	1. txHash string： 交易hash
	输出：
	交易数据

###GetRawTransactionVerbose

	功能：根据txhash从区块链上查询交易数据（包含区块信息）
	输入：
	1. txHash string： 交易hash
	输出：
	交易数据
	
###GetRawMempool

	功能：从全节点内存中获取内存中的交易数据
	输出：
	交易hash列表
	
###GetBlockInfoByHeight

	功能：根据区块高度获取区块信息
	输入：
	1. height int64： 高度
	输出：
	区块对象

###GetBlockInfoByHash

	功能：根据区块hash获取区块信息
	输入：
	1. hash string： 区块hash
	输出：
	区块对象
	
###SendRawTransaction

	功能：发送交易数据到全节点
	输入：
	1.tx *wire.MsgTx： 交易对象
	输出：
	交易hash
	
#common func接口

###ExtractPkScriptAddr

	功能：从输出脚本中提取地址
	输入：
	1.PkScript []byte：交易输出脚本
	2.coinType string： 币类型
	输出：
	地址

###ExtractPkScriptMessage

	功能：从NullDataTy脚本中提取信息
	输入：
	1. PkScript []byte:  交易输出脚本
	输出：
	脚本message
	
###GetMultiSigAddress

	功能：通过公钥列表生成多签地址、兑现脚本
	输入：
	1.addressPubkeyList []string： 公钥列表
	2.nrequired int：多签地址需要几个签名
	3.coinType string: 币类型
	输出：
	1. 多签地址
	2. 兑现脚本
	3. error


###CalcBip143SignatureHash

	功能：bch中对交易数据生成bip143签名hash
	输入：
	1.subScript []byte： 脚本
	2. sigHashes *txscript.TxSigHashes： 交易hash
	3. hashType txscript.SigHashType: hash类型
	4. tx *wire.MsgTx： 交易数据
	5. idx int：输入索引
	6. amt int64： 金额
	输出：
	hash
	
###RawTxInSignature

	功能：使用签名服务，对交易数据进行签名
	输入：
	1. tx *wire.MsgTx： 交易数据
	2. idx int： 输入索引
	3. subScript []byte： 兑现脚本
	4. hashType txscript.SigHashType： hash类型
	5. value int64： 金额
	6. coinType string： 币类型
	7. nodePubKeyHash string： 签名服务公钥
	输出：
	签名
	
###DecodeAddress

	功能：从地址字符串中decode Address
	输入：
	1. addr string: 地址字符串
	2. coinType string：币类型
	输出：
	地址对象

###CoinSelect

	功能： utxo挑选算法
	输入：
	1.utxoList []*UtxoInfo: utxo列表
	2.targetValue int64: 支出金额
	输出：
	挑选出的coin列表
	
