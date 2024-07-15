package core

import (
	glog "gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xjasonlyu/tun2socks/v2/component/remotedns"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
)

func withUDPHandler(handle func(adapter.UDPConn)) option.Option {
	return func(s *stack.Stack) error {
		s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, ptr *stack.PacketBuffer) bool {
			if remotedns.HandleDNSQuery(s, id, ptr) {
				return true
			}

			udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
				var (
					wq waiter.Queue
					id = r.ID()
				)
				ep, err := r.CreateEndpoint(&wq)
				if err != nil {
					glog.Debugf("foward udp request %s:%d->%s:%d: %s",
						id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort, err)
					return
				}

				conn := &udpConn{
					UDPConn: gonet.NewUDPConn(&wq, ep),
					id:      id,
				}
				handle(conn)
			})
			return udpForwarder.HandlePacket(id, ptr)
		})
		return nil
	}
}

type udpConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *udpConn) ID() *stack.TransportEndpointID {
	return &c.id
}
