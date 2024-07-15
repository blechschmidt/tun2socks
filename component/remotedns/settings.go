package remotedns

import (
	"errors"
	"net"
	"time"
)

// The timeout is somewhat arbitrary. For example, netcat will resolve the DNS
// names upon startup and then stick to the resolved IP address. A timeout of 1
// second may therefore be too low in cases where the first UDP packet is not
// sent immediately.
const (
	minTimeout = 30 * time.Second
)

var (
	enabled             = false
	ip4net              *net.IPNet
	ip4NextAddress      net.IP
	ip4BroadcastAddress net.IP
)

func IsEnabled() bool {
	return enabled
}

func SetCacheTimeout(timeout time.Duration) error {
	if timeout < minTimeout {
		timeout = minTimeout
	}
	ttl = uint32(timeout.Seconds())

	// Keep the value a little longer in cache than propagated via DNS
	return cache.SetTTL(timeout + 10*time.Second)
}

func SetNetwork(ipnet *net.IPNet) error {
	leadingOnes, _ := ipnet.Mask.Size()
	if len(ipnet.IP) == 4 {
		if leadingOnes > 30 {
			return errors.New("IPv4 remote DNS subnet too small")
		}
		ip4net = ipnet
	} else {
		return errors.New("unsupported protocol")
	}
	return nil
}

func Enable() {
	ip4NextAddress = incrementIp(getNetworkAddress(ip4net))
	ip4BroadcastAddress = getBroadcastAddress(ip4net)
	enabled = true
}
