package sflow

import (
	"time"

	"github.com/elastic/beats/packetbeat/protos"
)

type sflowConfig struct {
	Ports              []int         `config:"ports"`
	SampleType         []string      `config:"sample_type"`
	TransactionTimeout time.Duration `config:"transaction_timeout"`
}

var (
	defaultConfig = sflowConfig{
		TransactionTimeout: protos.DefaultTransactionExpiration,
	}
)
