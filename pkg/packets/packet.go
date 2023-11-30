// Package packets searches for a string in a TCP/UDP packet
package packets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

// PacketData is an interface that defines the methods required to process TCP or UDP layer
type PacketData interface {
	LayerPayload() []byte
}

// StringPacketFinder - Searches for a string in a TCP or UDP packet
type StringPacketFinder interface {
	FindStringInTCPOrUDPPacket(
		ctx context.Context,
		gp gopacket.Packet,
		searchString string,
	) (bool, error)
}

// Sentinel errors for various scenarios
var (
	ErrNonTCPUDPPacket  = errors.New("not a tcp or a UDP packet")
	ErrEmptyStringMatch = errors.New("empty string can not be matched against the packet data")
	ErrNilPacket        = errors.New("nil packet sent for matching")
)

// StringSearchService - Exposes the Packet capture service
type StringSearchService struct {
	Log *zap.SugaredLogger
}

// NewStringSearchService - returns a new instance of the StringSearchService
func NewStringSearchService(log *zap.SugaredLogger) *StringSearchService {
	return &StringSearchService{
		Log: log,
	}
}

// FindStringInTCPOrUDPPacket - processes TCP or UDP packets and checks if the data payload contains a string
func (svc *StringSearchService) FindStringInTCPOrUDPPacket(
	ctx context.Context,
	gp gopacket.Packet,
	searchString string,
) (bool, error) {
	
	// result will hold the result of the packet processing and match
	type result struct {
		match bool
		err   error
	}
	
	// result channel will communicate the results of the processing
	resultCh := make(chan result)
	
	// Process the gp in a go routine
	go func(resultCh chan result, gp gopacket.Packet) {
		
		// check if the context has been cancelled by the caller
		select {
		case <-ctx.Done():
			r := result{
				match: false,
				err:   ctx.Err(),
			}
			resultCh <- r
		default:
		}
		
		var (
			tcpLayer    = gp.Layer(layers.LayerTypeTCP)
			udpLayer    = gp.Layer(layers.LayerTypeUDP)
			packetLayer gopacket.Layer
			msg         string
		)
		
		// we only work with TCP or UDP packets
		// and assume that the caller of the function will only send a TCP/UDP packet
		// this is taken care by using a BPF filter `tcp or udp` in the main routine
		if tcpLayer == nil && udpLayer == nil {
			svc.Log.Error(ErrNonTCPUDPPacket)
			r := result{
				match: false,
				err:   ErrNonTCPUDPPacket,
			}
			resultCh <- r
			return
		}
		
		if tcpLayer != nil {
			// tempLayer is local scoped here
			tempLayer, ok := tcpLayer.(*layers.TCP)
			if !ok {
				r := result{
					match: false,
					err:   nil,
				}
				resultCh <- r
				return
			}
			msg = fmt.Sprintf("sourcePort:%q destinationPort=%q", tempLayer.SrcPort, tempLayer.DstPort)
			packetLayer = tempLayer
		}
		
		if udpLayer != nil {
			// tempLayer is local scoped here
			tempLayer, ok := udpLayer.(*layers.UDP)
			if !ok {
				r := result{
					match: false,
					err:   nil,
				}
				resultCh <- r
				return
			}
			msg = fmt.Sprintf("sourcePort:%q destinationPort=%q", tempLayer.SrcPort, tempLayer.DstPort)
			packetLayer = tempLayer
		}
		
		// if IPv4 layer exists then we can print the source and the destination of the packet
		if ipLayer := gp.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			if ipv4Layer, ok := ipLayer.(*layers.IPv4); ok {
				msg = fmt.Sprintf("Packet Details: %s sourceIP=%q, destinationIP=%q",
					msg, ipv4Layer.SrcIP, ipv4Layer.DstIP)
			}
		}
		
		// search for the string in the packet
		foundMatch, matchErr := svc.searchStringInPacket(packetLayer, searchString)
		
		if foundMatch {
			// if match is found then output the packet details
			svc.Log.Info("found match ", msg)
		}
		
		r := result{
			match: foundMatch,
			err:   matchErr,
		}
		
		resultCh <- r
		
	}(resultCh, gp)
	
	// wait for the result channel or the context to be cancelled
	select {
	case res := <-resultCh:
		return res.match, res.err
	case <-ctx.Done():
		return false, ctx.Err()
	}
	
}

// searchStringInPacket - searches for a string in PacketData
func (svc *StringSearchService) searchStringInPacket(data PacketData, searchStr string) (bool, error) {
	
	if data == nil {
		svc.Log.Errorf("nil packet was passed for processing")
		return false, ErrNilPacket
	}
	
	if searchStr == "" {
		svc.Log.Errorf("empty string can not be searched on the packet payload")
		return false, ErrEmptyStringMatch
	}
	
	// grab the data contained in the packet
	payload := data.LayerPayload()
	
	if len(payload) <= 0 {
		svc.Log.Debug("skipping processing of packet that has no data")
		return false, nil
	}
	
	payloadStr := string(payload)
	
	// this is a case-sensitive match
	if strings.Contains(payloadStr, searchStr) {
		svc.Log.Infof("found string %q in the packet payload", searchStr)
		return true, nil
	}
	
	return false, nil
}
