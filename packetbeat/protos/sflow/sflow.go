package sflow

import (
	"bytes"
	"encoding/json"
	"time"

	vpacket "github.com/VerizonDigital/vflow/packet"
	vsflow "github.com/VerizonDigital/vflow/sflow"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
)

type sflowPlugin struct {
	// Configuration data.
	ports              []int
	sendRequest        bool
	sendResponse       bool
	includeAuthorities bool
	includeAdditionals bool

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
	return nil
}

func (sflow *sflowPlugin) setFromConfig(config *sflowConfig) error {
	sflow.ports = config.Ports
	sflow.ports = config.Ports
	sflow.sendRequest = config.SendRequest
	sflow.sendResponse = config.SendResponse
	sflow.transactionTimeout = config.TransactionTimeout
	return nil
}

func (sflow *sflowPlugin) GetPorts() []int {
	return sflow.ports
}

func (sflow *sflowPlugin) ParseUDP(pkt *protos.Packet) {
	var (
		filter = []uint32{vsflow.DataCounterSample}
		b      []byte
	)
	defer logp.Recover("Sflow ParseUdp")
	packetSize := len(pkt.Payload)
	debugf("Parsing packet addressed with %s of length %d.", pkt.Tuple.String(), packetSize)
	debugf("Sflow packet data: %X", pkt.Payload)
	reader := bytes.NewReader(pkt.Payload)
	d := vsflow.NewSFDecoder(reader, filter)
	records, err := d.SFDecode()
	if err != nil || len(records) < 1 {
		return
	}

	decodeMsg := vsflow.Message{}

	for _, data := range records {
		switch data.(type) {
		case *vpacket.Packet:
			decodeMsg.Packet = data.(*vpacket.Packet)
		case *vsflow.ExtSwitchData:
			decodeMsg.ExtSWData = data.(*vsflow.ExtSwitchData)
		case *vsflow.FlowSample:
			decodeMsg.Sample = data.(*vsflow.FlowSample)
		case *vsflow.SFDatagram:
			decodeMsg.Header = data.(*vsflow.SFDatagram)
		}
	}

	b, err = json.Marshal(decodeMsg)
	if err != nil {
		logp.Err("Json err: %s", err.Error())
		return
	}
	debugf("Unpack result:%v", b)
}
