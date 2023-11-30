package main

import (
	"context"
	"fmt"
	"time"
	
	"github.com/google/gopacket"
	"go.uber.org/zap"
	
	"github.com/controlplaneio/netassertv2-packet-sniffer/pkg/packets"
)

// processPackets - processes the packets and searches for the string
func processPackets(
	ctx context.Context,
	packetSource *gopacket.PacketSource,
	lg *zap.SugaredLogger,
	cfg *config,
	cs packets.StringPacketFinder,
) error {
	
	timer := time.NewTimer(time.Duration(cfg.TimeoutSeconds) * time.Second)
	defer func() { _ = timer.Stop() }()
	count := 0
	
	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timeout while searching for string %s in packets", cfg.SearchString)
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while searching for string in packets: %w", ctx.Err())
		case packet := <-packetSource.Packets():
			// try to find the string in the packet
			found, err := cs.FindStringInTCPOrUDPPacket(ctx, packet, cfg.SearchString)
			if err != nil {
				lg.Warnw("encountered error while processing a packet - %v", err)
			}
			
			if found { // string was found in the packet
				count++ // increment the count
				lg.Infow("string found in packet", "count", count)
			}
			
			if count >= cfg.NumberOfMatches {
				lg.Infow("number of matches reached", "count", count)
				return nil
			}
		}
	}
	
}
