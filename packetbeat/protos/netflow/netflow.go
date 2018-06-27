package netflow

import (
	"bytes"
	"net"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
)

type netflowPlugin struct {
	// Configuration data.
	ports   []int
	version []int

	// Cache of active netflow transactions. The map key is the HashableDnsTuple
	// associated with the request.
	transactions       *common.Cache
	transactionTimeout time.Duration

	results protos.Reporter // Channel where results are pushed.
}

var (
	debugf = logp.MakeDebug("netflow")
)

func init() {
	protos.Register("netflow", New)
}

// New create and initializes a new netflow protocol analyzer instance.
func New(
	testMode bool,
	results protos.Reporter,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &netflowPlugin{}
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

func (netflow *netflowPlugin) init(results protos.Reporter, config *netflowConfig) error {
	netflow.setFromConfig(config)
	netflow.transactions = common.NewCache(
		netflow.transactionTimeout,
		protos.DefaultTransactionHashSize)
	netflow.transactions.StartJanitor(netflow.transactionTimeout)
	netflow.results = results
	return nil
}

func (netflow *netflowPlugin) setFromConfig(config *netflowConfig) error {
	netflow.ports = config.Ports
	netflow.version = config.Version
	netflow.transactionTimeout = config.TransactionTimeout
	return nil
}

func (netflow *netflowPlugin) GetPorts() []int {
	return netflow.ports
}

func (netflow *netflowPlugin) ParseUDP(pkt *protos.Packet) {
	defer logp.Recover("Netflow ParseUdp")
	packetSize := len(pkt.Payload)
	debugf("Parsing packet addressed with %s of length %d.", pkt.Tuple.String(), packetSize)
	debugf("Netflow packet data: %X", pkt.Payload)
	t := pkt.Ts
	reader := bytes.NewReader(pkt.Payload)
	d := NewNFDecoder(reader, t, netflow.version, pkt.Tuple.SrcIP)
	records, err := d.Decode()
	if err != nil {
		debugf("Netflow decode error：%s", err.Error())
		return
	}
	netflow.publishTransaction(records, t, pkt.Tuple.SrcIP)
	debugf("Unpack result:%v", records)
}

func (netflow *netflowPlugin) publishTransaction(d NTrans, t time.Time, agent net.IP) {
	for _, event := range d.TransInfo() {
		event["agent"] = agent
		netflow.results(beat.Event{
			Timestamp: t,
			Fields:    event,
		})
	}
}
