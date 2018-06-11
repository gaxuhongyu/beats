package netflow

import (
	"time"

	"github.com/elastic/beats/packetbeat/protos"
)

type netflowConfig struct {
	Ports              []int         `config:"ports"`
	Version            []int         `config:"version"`
	TransactionTimeout time.Duration `config:"transaction_timeout"`
}

var (
	defaultConfig = netflowConfig{
		TransactionTimeout: protos.DefaultTransactionExpiration,
	}
)
