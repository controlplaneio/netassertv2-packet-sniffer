// main package is the entrypoint of this program
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	
	"github.com/ardanlabs/conf/v3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	
	"github.com/controlplaneio/netassertv2-packet-sniffer/pkg/logger"
	"github.com/controlplaneio/netassertv2-packet-sniffer/pkg/packets"
)

var (
	version = "development"    // version that will be overridden by LD flag(s)
	service = "packet-capture" // service/application name to be overridden by LD flag
)

// config - holds the configuration for this program
type config struct {
	NetworkInterface string `conf:"default:eth0,flag:interface,env:IFACE"`
	SnapLen          int32  `conf:"default:1024,flag:snaplen,env:SNAPLEN"`
	Promisc          bool   `conf:"default:false,flag:promisc,env:PROMISC"`
	SearchString     string `conf:"default:control-plane.io,flag:search-string,env:SEARCH_STRING"`
	Protocol         string `conf:"default:tcp,flag:protocol,env:PROTOCOL"`
	// environment can be production or development
	Environment     string `conf:"default:production,flag:environment,env:ENV"`
	NumberOfMatches int    `conf:"default:3,flag:matches,env:MATCHES"`
	TimeoutSeconds  int    `conf:"default:60,flag:timeout-seconds,env:TIMEOUT_SECONDS"`
}

// processTimeout - time to process each packet
const processTimeout = 500 * time.Millisecond

// initConfigAndLogger - initialises the configuration and logger
func initConfigAndLogger() (*config, *zap.SugaredLogger, error) {
	var cfg config
	// Parse the config struct to get the configuration
	help, err := conf.Parse("", &cfg)
	
	if err != nil {
		if errors.Is(err, conf.ErrHelpWanted) {
			fmt.Println(help)
			return nil, nil, conf.ErrHelpWanted
		}
		return nil, nil, fmt.Errorf("parsing config failed: %v", err)
	}
	
	lg, err := logger.New(version, service, cfg.Environment)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialise the logger: %w", err)
	}
	
	return &cfg, lg, nil
}

// setupPacketCapture - sets up the packet capture
func setupPacketCapture(cfg *config) (*pcap.Handle, error) {
	// Set up packet capture
	
	handle, err := pcap.OpenLive(
		cfg.NetworkInterface, // name of the interface to capture
		cfg.SnapLen,          // snap length
		cfg.Promisc,          // set the interface in promiscuous mode
		processTimeout,       // ticker
	)
	
	if err != nil {
		return nil, fmt.Errorf("unable to capture packet on the %q interface - %w",
			cfg.NetworkInterface, err)
	}
	
	if err := handle.SetBPFFilter(strings.ToLower(cfg.Protocol)); err != nil {
		return nil, fmt.Errorf("unable to set BPF filter to %q: %v", cfg.Protocol, err)
	}
	return handle, nil
}

// entrypoint of this program
func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	
	cfg, lg, err := initConfigAndLogger()
	if err != nil {
		return fmt.Errorf("failed to initialise the config and logger: %w", err)
	}
	
	defer func() {
		_ = lg.Sync()
	}()
	
	lg.Infof("Working with following configuration:\n%+v\n", cfg)
	
	// setup up the packet capture
	handle, err := setupPacketCapture(cfg)
	
	if err != nil {
		return fmt.Errorf("unable to capture packet on the %s interface - %v", cfg.NetworkInterface, err)
	}
	
	//nolint:staticcheck // Close function does not return anything
	defer handle.Close()
	
	lg.Infof("capturing %q traffic on %q interface", cfg.Protocol, cfg.NetworkInterface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	lg.Info("starting to process packets")
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	signalChan := make(chan os.Signal, 1)
	defer close(signalChan)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGQUIT)
	result := make(chan error)
	defer close(result)
	
	// create a new instance of the StringSearchService
	svc := packets.NewStringSearchService(lg)
	
	go func() { // start a goroutine to process the packets
		result <- processPackets(ctx, packetSource, lg, cfg, svc)
	}()
	
	select { // wait for the result or signal
	case err := <-result:
		if err != nil {
			return fmt.Errorf("unable to find string %s in %s packets: %w", cfg.SearchString, cfg.Protocol, err)
		}
		return err
	
	case sig := <-signalChan:
		lg.Infof("received signal %v from OS, quitting", sig)
		cancel()
		return fmt.Errorf("context cancelled while searching for string in packets: %w", ctx.Err())
	}
	
}
