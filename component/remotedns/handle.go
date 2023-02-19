package remotedns

import (
	"net"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

func RewriteMetadata(metadata *M.Metadata) bool {
	if !IsEnabled() {
		return false
	}
	dstName, found := getCachedName(metadata.DstIP)
	if !found {
		return false
	}
	metadata.VirtualIP = metadata.DstIP
	metadata.DstIP = nil
	metadata.DstName = dstName.(string)
	return true
}

func HandleDNSQuery(s *stack.Stack, id stack.TransportEndpointID, ptr stack.PacketBufferPtr) bool {
	if !IsEnabled() {
		return false
	}

	msg := dns.Msg{}
	err := msg.Unpack(ptr.Data().AsRange().ToSlice())

	// Ignore UDP packets that are not IP queries to a recursive resolver
	if id.LocalPort != 53 || err != nil || len(msg.Question) != 1 || msg.Question[0].Qtype != dns.TypeA &&
		msg.Question[0].Qtype != dns.TypeAAAA || msg.Question[0].Qclass != dns.ClassINET || !msg.RecursionDesired ||
		msg.Response {
		return false
	}

	qname := msg.Question[0].Name
	qtype := msg.Question[0].Qtype

	log.Infof("[DNS] query %s %s", dns.TypeToString[qtype], qname)

	msg.RecursionDesired = false
	msg.RecursionAvailable = true
	var ip net.IP
	if qtype == dns.TypeA {
		rr := dns.A{}
		ip = insertNameIntoCache(4, qname)
		if ip == nil {
			log.Warnf("[DNS] IP space exhausted")
			return true
		}
		rr.A = ip
		rr.Hdr.Name = qname
		rr.Hdr.Ttl = ttl
		rr.Hdr.Class = dns.ClassINET
		rr.Hdr.Rrtype = qtype
		msg.Answer = append(msg.Answer, &rr)
	}

	msg.Response = true
	msg.RecursionAvailable = true

	var wq waiter.Queue

	ep, err2 := s.NewEndpoint(ptr.TransportProtocolNumber, ptr.NetworkProtocolNumber, &wq)
	if err2 != nil {
		return true
	}
	defer ep.Close()

	ep.Bind(tcpip.FullAddress{NIC: ptr.NICID, Addr: id.LocalAddress, Port: id.LocalPort})
	conn := gonet.NewUDPConn(s, &wq, ep)
	defer conn.Close()
	packed, err := msg.Pack()
	if err != nil {
		return true
	}
	_, _ = conn.WriteTo(packed, &net.UDPAddr{IP: net.IP(id.RemoteAddress), Port: int(id.RemotePort)})
	return true
}
