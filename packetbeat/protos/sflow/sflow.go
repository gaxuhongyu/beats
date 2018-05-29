package sflow

import (
	"bytes"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
)

type sflowPlugin struct {
	// Configuration data.
	ports      []int
	sampleType []int

	// Cache of active sflow transactions. The map key is the HashableDnsTuple
	// associated with the request.
	transactions       *common.Cache
	transactionTimeout time.Duration

	results protos.Reporter // Channel where results are pushed.
}

var (
	debugf = logp.MakeDebug("sflow")
)

func init() {
	protos.Register("sflow", New)
}

// New create and initializes a new sflow protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &sflowPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (sflow *sflowPlugin) init(results protos.Reporter, config *sflowConfig) error {
	sflow.setFromConfig(config)
	sflow.transactions = common.NewCache(
		sflow.transactionTimeout,
		protos.DefaultTransactionHashSize)
	sflow.transactions.StartJanitor(sflow.transactionTimeout)
	sflow.results = results
	return nil
}

func (sflow *sflowPlugin) setFromConfig(config *sflowConfig) error {
	sflow.ports = config.Ports
	sflow.sampleType = config.SampleType
	sflow.transactionTimeout = config.TransactionTimeout
	return nil
}

func (sflow *sflowPlugin) GetPorts() []int {
	return sflow.ports
}

func (sflow *sflowPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("Sflow ParseUdp")
	packetSize := len(pkt.Payload)
	debugf("Parsing packet addressed with %s of length %d.", pkt.Tuple.String(), packetSize)
	debugf("Sflow packet data: %X", pkt.Payload)
	reader := bytes.NewReader(pkt.Payload)
	d := NewSFDecoder(reader, pkt.Ts, sflow.sampleType)
	records, err := d.SFDecode()
	if err != nil {
		debugf("SFDecode decode error：%s", err.Error())
		return
	}
	sflow.publishTransaction(records)
	debugf("Unpack result:%v", records)
}

func (sflow *sflowPlugin) publishTransaction(d []*SFTransaction) {
	for _, msg := range d {
		event := common.MapStr{
			"type": "sflow",
		}
		msg.datagram.TransInfo(event)
		for _, d := range msg.data {
			d.TransInfo(event)
		}
		sflow.results(beat.Event{
			Timestamp: msg.t,
			Fields:    event,
		})
	}
}
