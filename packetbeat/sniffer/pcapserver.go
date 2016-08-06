package sniffer

import (
	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
	"fmt"
	"time"
	"encoding/binary"
	zmq "github.com/pebbe/zmq4"
)

type PcapSubscriber struct {
	sub *zmq.Socket
	datalink layers.LinkType
	endian binary.ByteOrder
}

func NewPcapServerSubscriber(device string, subscription string) (*PcapSubscriber, error) {

	sock, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Using remote server %v with subscription %v\n", device, subscription)
	sock.Connect(device)
	sock.SetSubscribe(subscription)

	return &PcapSubscriber{sub:sock, endian:binary.LittleEndian}, nil
}

func (sub* PcapSubscriber) extractLink(data []byte) layers.LinkType {
	// struct pcap_file_header {
        // 0-3		bpf_u_int32 magic;
        // 4-5		u_short version_major;
        // 6-7		u_short version_minor;
        // 8-11		bpf_int32 thiszone;     /* gmt to local correction */
        // 12-15	bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        // 16-19	bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        // 20-23	bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
	// };

	// TODO: use magic to determine endian? Assume LittleEndian now
	return layers.LinkType(sub.endian.Uint32(data[20:24]))
}

func (sub *PcapSubscriber) extractData(pkt []byte) (data []byte, ci gopacket.CaptureInfo) {
	ci.Timestamp = time.Unix(
				int64(sub.endian.Uint32(pkt[0:4])),
				int64(sub.endian.Uint32(pkt[4:8])) * 1000)
	ci.CaptureLength = int(sub.endian.Uint32(pkt[8:12]))
	ci.Length = int(sub.endian.Uint32(pkt[12:16]))
	return pkt[16:], ci
}

func (sub *PcapSubscriber) Close() {
	sub.sub.Close()
}

func (sub *PcapSubscriber) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	msg, _ := sub.sub.RecvMessageBytes(0)

	// msg[0] == client name...
	// msg[1] == pcap_file_header
	// msg[2] == pcap_pkthdr + data
	sub.datalink = sub.extractLink(msg[1])
	data, ci = sub.extractData(msg[2])
	return data, ci, nil
}

func (sub *PcapSubscriber) LastLinkType() *layers.LinkType {
	return &sub.datalink
}
