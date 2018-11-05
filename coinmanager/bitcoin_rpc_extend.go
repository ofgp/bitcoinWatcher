package coinmanager

// EstimateFeeCmd defines the estimatefee JSON-RPC command.
type EstimateSmartFeeCmd struct {
	NumBlocks int64
}

// NewEstimateFeeCmd returns a new instance which can be used to issue a
// estimatefee JSON-RPC command.
func NewEstimateSmartFeeCmd(numBlocks int64) *EstimateSmartFeeCmd {
	return &EstimateSmartFeeCmd{
		NumBlocks: numBlocks,
	}
}

type EstimateSmartFeeResult struct {
	Feerate float64  `json:"feerate"`
	Blocks  int64    `json:"blocks"`
	Errors  []string `json:"errors"`
}
