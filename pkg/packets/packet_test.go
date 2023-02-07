package packets

import (
	"context"
	"testing"

	"github.com/controlplaneio/packet-capture-netassert/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func createTCPUDPPacket(t *testing.T, payload string, protocol string) gopacket.Packet {

	buf := gopacket.NewSerializeBuffer()

	// Set up layers for the packet
	tcpLayer := &layers.TCP{
		SrcPort:    12345,
		DstPort:    54321,
		Seq:        1,
		Ack:        1,
		DataOffset: 5,
		Window:     123,
		Urgent:     0,
		SYN:        true,
		ACK:        true,
	}

	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   12345,
		DstPort:   9090,
	}

	var err error
	var packet gopacket.Packet

	switch protocol {
	case "tcp":
		// Serialize the TCP packet
		err = gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{},
			tcpLayer,
			gopacket.Payload([]byte(payload)),
		)
		// Serialize the UDP packet
	case "udp":
		// Serialize the UDP packet
		err = gopacket.SerializeLayers(buf,
			gopacket.SerializeOptions{},
			udpLayer,
			gopacket.Payload([]byte(payload)),
		)
	default:
		t.Fatalf("only support protocol tcp or udp and not %q", protocol)
	}

	if err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	if protocol == "tcp" {
		packet = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeTCP, gopacket.Default)
	}

	if protocol == "udp" {
		packet = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeUDP, gopacket.Default)
	}

	if err := packet.ErrorLayer(); err != nil {
		t.Fatal("error decoding some part of the packet:", err)
	}

	return packet
}

func TestFindStringInTCPOrUDPPacket(t *testing.T) {

	tt := []struct {
		name         string
		err          error
		want         bool
		packetString string
		searchString string
		protocol     string
	}{
		{
			`when string searched is present in the TCP packet`,
			nil,
			true,
			"foo",
			"foo",
			"tcp",
		},
		{
			`when string searched is not present in the TCP packet`,
			nil,
			false,
			"foo",
			"bar",
			"tcp",
		},
		{
			`when empty string is searched in the TCP packet`,
			ErrEmptyStringMatch,
			false,
			"foo",
			"",
			"tcp",
		},
		{
			`when string searched is present in the UDP packet`,
			nil,
			true,
			"foo",
			"foo",
			"udp",
		},
		{
			`when string searched is not present in the UDP packet`,
			nil,
			false,
			"foo",
			"bar",
			"udp",
		},
	}

	req := require.New(t)
	lg, err := logger.New("test", "test", "development")
	req.Nil(err, "failed to initialise the logger")

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := StringSearchService{
				Log: lg,
			}
			ctx := context.Background()
			packet := createTCPUDPPacket(t, tc.packetString, tc.protocol)
			got, gotError := cs.FindStringInTCPOrUDPPacket(ctx, packet, tc.searchString)
			req.Equal(tc.err, gotError)
			req.Equal(tc.want, got)
		})

	}
}

// test with non tcp and udp packets
func TestFindStringInTCPOrUDPPacket_WithNonTCPUDPPacket(t *testing.T) {

	tt := []struct {
		name      string
		wantError error
		want      bool
		layer     gopacket.LayerType
		payload   string
	}{
		{"test with packet that only has IPV4 layer",
			ErrNonTCPUDPPacket,
			false,
			layers.LayerTypeIPv4,
			"testingData",
		},
		{"test with packet that only has IPV4 layer",
			ErrNonTCPUDPPacket,
			false,
			layers.LayerTypeEthernet,
			"testingData",
		},
	}
	req := require.New(t)
	ctx := context.Background()
	lg, err := logger.New("test", "test", "development")
	req.Nil(err, "failed to initialise the logger")
	cs := StringSearchService{
		Log: lg,
	}

	for _, tc := range tt {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			packet := gopacket.NewPacket([]byte(tc.payload), layers.LayerTypeIPv4, gopacket.Default)
			got, gotErr := cs.FindStringInTCPOrUDPPacket(ctx, packet, "foobar")
			req.Equal(tc.wantError, gotErr)
			req.Equal(tc.want, got)
		})
	}

}
