/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"unicode"

	"github.com/daeuniverse/dae/common/consts"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Endpoint struct {
	TCP  bool
	UDP  bool
	Addr string
}

var ErrBadLocalDNSBindFormat = errors.New("bad local dns bind format")

func ParseEndpoint(raw string) (endpoint Endpoint, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Endpoint{}, fmt.Errorf("%w: empty endpoint", ErrBadLocalDNSBindFormat)
	}

	_, _, perr := net.SplitHostPort(raw)
	if perr == nil {
		return Endpoint{UDP: true, Addr: raw}, nil
	}

	u, perr := url.Parse(raw)
	if perr != nil {
		return Endpoint{}, fmt.Errorf("%w: %v", ErrBadLocalDNSBindFormat, perr)
	}
	if u.Host == "" {
		return Endpoint{}, fmt.Errorf("%w: missing host for %s", ErrBadLocalDNSBindFormat, raw)
	}

	endpoint.Addr = u.Host
	for _, scheme := range strings.Split(u.Scheme, "+") {
		switch scheme {
		case "udp":
			endpoint.UDP = true
		case "tcp":
			endpoint.TCP = true
		default:
			return Endpoint{}, fmt.Errorf(
				"%w: unsupported protocol: %s for %s",
				ErrBadLocalDNSBindFormat, scheme, raw,
			)
		}
	}
	if !endpoint.TCP && !endpoint.UDP {
		return Endpoint{}, fmt.Errorf("%w: missing protocol for %s", ErrBadLocalDNSBindFormat, raw)
	}
	return endpoint, nil
}

func ParseEndpoints(raw string) ([]Endpoint, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: empty endpoint list", ErrBadLocalDNSBindFormat)
	}

	endpoints := make([]Endpoint, 0, len(parts))
	for _, part := range parts {
		endpoint, err := ParseEndpoint(part)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

type DNSListener struct {
	log        *logrus.Logger
	servers    []*dnsmessage.Server
	endpoints  []Endpoint
	controller *ControlPlane
	mu         sync.Mutex
}

// NewDNSListener creates a new DNS listener.
func NewDNSListener(log *logrus.Logger, endpoint string, controller *ControlPlane) (*DNSListener, error) {
	endpoints, err := ParseEndpoints(endpoint)
	if err != nil {
		return nil, err
	}

	return &DNSListener{
		log:        log,
		controller: controller,
		endpoints:  endpoints,
	}, nil
}

func (d *DNSListener) Addr() string {
	addrs := make([]string, 0, len(d.endpoints))
	for _, endpoint := range d.endpoints {
		addrs = append(addrs, endpoint.Addr)
	}
	return strings.Join(addrs, ",")
}

// Start starts the DNS listener.
func (d *DNSListener) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.servers) > 0 {
		return fmt.Errorf("DNS listener already started")
	}

	handler := &dnsHandler{
		controller: d.controller,
		log:        d.log,
	}

	servers, err := createDNSServers(d.endpoints, handler)
	if err != nil {
		return err
	}

	d.servers = servers
	for i, server := range d.servers {
		if err := d.serve(server); err != nil {
			for _, started := range d.servers[:i] {
				_ = started.Shutdown()
			}
			closeDNSServers(d.servers[i:])
			d.servers = nil
			return err
		}
	}
	return nil
}

func createDNSServers(endpoints []Endpoint, handler dnsmessage.Handler) ([]*dnsmessage.Server, error) {
	servers := make([]*dnsmessage.Server, 0, len(endpoints)*2)
	for _, endpoint := range endpoints {
		if endpoint.UDP {
			packetConn, err := net.ListenPacket("udp", endpoint.Addr)
			if err != nil {
				closeDNSServers(servers)
				return nil, fmt.Errorf("listen DNS UDP on %s: %w", endpoint.Addr, err)
			}
			servers = append(servers, &dnsmessage.Server{
				Addr:       packetConn.LocalAddr().String(),
				Net:        "udp",
				PacketConn: packetConn,
				Handler:    handler,
				UDPSize:    65535,
			})
		}
		if endpoint.TCP {
			listener, err := net.Listen("tcp", endpoint.Addr)
			if err != nil {
				closeDNSServers(servers)
				return nil, fmt.Errorf("listen DNS TCP on %s: %w", endpoint.Addr, err)
			}
			servers = append(servers, &dnsmessage.Server{
				Addr:     listener.Addr().String(),
				Net:      "tcp",
				Listener: listener,
				Handler:  handler,
			})
		}
	}
	return servers, nil
}

func closeDNSServers(servers []*dnsmessage.Server) {
	for _, server := range servers {
		if server.PacketConn != nil {
			_ = server.PacketConn.Close()
		}
		if server.Listener != nil {
			_ = server.Listener.Close()
		}
	}
}

func (d *DNSListener) serve(server *dnsmessage.Server) error {
	started := make(chan error, 1)
	network := strings.ToUpper(server.Net)
	server.NotifyStartedFunc = func() {
		started <- nil
	}
	go func() {
		d.log.Infof("Starting DNS %s listener on %s", network, server.Addr)
		if err := server.ActivateAndServe(); err != nil {
			select {
			case started <- err:
			default:
				d.log.Errorf("Failed to serve DNS %s listener on %s: %v", network, server.Addr, err)
			}
		}
	}()
	return <-started
}

// Stop stops the DNS listener.
func (d *DNSListener) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	for _, server := range d.servers {
		if err := server.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	d.servers = nil

	if len(errs) > 0 {
		return fmt.Errorf("failed to stop DNS servers: %v", errors.Join(errs...))
	}
	return nil
}

// dnsHandler implements the dns.Handler interface.
type dnsHandler struct {
	controller *ControlPlane
	log        *logrus.Logger
}

// ServeDNS handles DNS requests.
func (h *dnsHandler) ServeDNS(w dnsmessage.ResponseWriter, r *dnsmessage.Msg) {
	select {
	case <-h.controller.ctx.Done():
		return
	case <-h.controller.ready:
	}
	clientIPPort, err := addrPortFromNetAddr(w.RemoteAddr())
	if err != nil {
		h.log.Errorf("Failed to parse client address: %v", err)
		return
	}

	localIPPort, err := addrPortFromNetAddr(w.LocalAddr())
	if err != nil {
		h.log.Errorf("Failed to parse local DNS listener address: %v", err)
		return
	}

	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
	}
	udpReq := &udpRequest{
		realSrc:       clientIPPort,
		realDst:       localIPPort,
		src:           clientIPPort,
		routingResult: routingResult,
	}

	err = h.controller.dnsController.HandleWithResponseWriter_(r, udpReq, w)
	if err != nil {
		h.log.Errorf("Failed to handle DNS request: %v", err)
		m := new(dnsmessage.Msg)
		m.SetRcode(r, dnsmessage.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, error) {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		addrPort := addr.AddrPort()
		return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
	case *net.UDPAddr:
		addrPort := addr.AddrPort()
		return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
	}
	if addr == nil {
		return netip.AddrPort{}, fmt.Errorf("nil net.Addr")
	}
	return netip.ParseAddrPort(addr.String())
}
