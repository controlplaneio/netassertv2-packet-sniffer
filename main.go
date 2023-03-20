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
  "github.com/controlplaneio/netassertv2-packet-sniffer/pkg/logger"
  "github.com/controlplaneio/netassertv2-packet-sniffer/pkg/packets"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

var (
  version = "development"    // version that will be overridden by LD flag(s)
  service = "packet-capture" // service/application name to be overridden by LD flag

)

// processTimeout - time to process each packet
const processTimeout = 500 * time.Millisecond

func main() {

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

  var (
    cfg   config
    found bool // string was found in the packet
  )

  help, err := conf.Parse("", &cfg)

  if err != nil {
    if errors.Is(err, conf.ErrHelpWanted) {
      fmt.Println(help)
      os.Exit(0)
    }
    fmt.Printf("parsing config failed: %v", err)
    os.Exit(1)
  }

  lg, err := logger.New(version, service, cfg.Environment)
  if err != nil {
    fmt.Println("failed to initialise the logger", err)
    os.Exit(1)
  }

  defer func() {
    _ = lg.Sync()
  }()

  lg.Infof("Working with following configuration:\n%+v\n", cfg)
  handle, err := pcap.OpenLive(
    cfg.NetworkInterface, // name of the interface to capture
    cfg.SnapLen,          // snap length
    cfg.Promisc,          // set the interface in promiscuous mode
    processTimeout,       // ticker
  )

  //nolint:staticcheck // Close function does not return anything
  defer handle.Close()

  if err != nil {
    lg.Infof("unable to capture packet on the %s interface - %v", cfg.NetworkInterface, err)
    _ = lg.Sync()
    os.Exit(1)
  }

  if err := handle.SetBPFFilter(strings.ToLower(cfg.Protocol)); err != nil {
    lg.Infof("unable to set BPF filter to %q: %v", cfg.Protocol, err)
    _ = lg.Sync()
    handle.Close()
    os.Exit(1)
  }

  cs := packets.StringSearchService{
    Log: lg,
  }

  lg.Infof("capturing %q traffic on %q interface", cfg.Protocol, cfg.NetworkInterface)
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

  lg.Info("starting to process packets")

  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  signalChan := make(chan os.Signal, 1)
  signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
  noOfMatchesReachedCh := make(chan struct{})

  timer := time.NewTimer(time.Duration(cfg.TimeoutSeconds) * time.Second)
  defer func() { timer.Stop() }()

  go func(ctx context.Context) {

    count := 0

    for packet := range packetSource.Packets() {

      matchResult, err := cs.FindStringInTCPOrUDPPacket(ctx, packet, cfg.SearchString)

      if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
        break
      }

      if err != nil {
        cs.Log.Errorf("encounterd error while processing a packet - %v", err)
        continue
      }

      if matchResult {
        count++
      }

      if count >= cfg.NumberOfMatches {
        noOfMatchesReachedCh <- struct{}{} // notify that we are done here
        return
      }

    }

  }(ctx)

  select {
  case <-noOfMatchesReachedCh:
    cs.Log.Infof("number of matches reached")
    cancel()
    found = true // string was found in the packet(s)
    break
  case sig := <-signalChan:
    cs.Log.Infof("received signal %v from OS, quitting", sig)
    cancel()
    break
  case <-timer.C:
    cs.Log.Infof("time out of %v seconds reached", cfg.TimeoutSeconds)
    cancel()
  }

  if !found {
    cs.Log.Infof("unable to find string %s in %s packets", cfg.SearchString, cfg.Protocol)
    handle.Close()
    _ = lg.Sync()
    _ = timer.Stop()
    os.Exit(1)
  }

}
