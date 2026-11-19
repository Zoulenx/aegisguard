package locker

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const ntpEpochOffset = 2208988800 // Seconds between 1900-01-01 and 1970-01-01

var defaultNTPServers = []string{
	"time.cloudflare.com:123",
	"time.google.com:123",
	"pool.ntp.org:123",
}

// TimeProvider abstracts verified network time vs local time for testing and clock-tamper defense.
type TimeProvider interface {
	VerifiedUTC() (now time.Time, fromNetwork bool)
}

type NTPTimeProvider struct {
	Servers []string
	Timeout time.Duration
}

func NewNTPTimeProvider() *NTPTimeProvider {
	return &NTPTimeProvider{
		Servers: defaultNTPServers,
		Timeout: 2 * time.Second,
	}
}

func (p *NTPTimeProvider) VerifiedUTC() (time.Time, bool) {
	for _, srv := range p.Servers {
		t, err := QueryNTP(srv, p.Timeout)
		if err == nil {
			return t.UTC(), true
		}
	}
	return time.Now().UTC(), false
}

// QueryNTP performs a lightweight SNTP (RFC 4330) UDP request to get tamper-proof UTC time.
func QueryNTP(server string, timeout time.Duration) (time.Time, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := make([]byte, 48)
	req[0] = 0x1B // LI=0, VN=3, Mode=3 (Client)
	if _, err := conn.Write(req); err != nil {
		return time.Time{}, err
	}
	resp := make([]byte, 48)
	n, err := conn.Read(resp)
	if err != nil || n < 48 {
		return time.Time{}, errors.New("invalid ntp response")
	}
	secs := binary.BigEndian.Uint32(resp[40:44])
	if secs < ntpEpochOffset {
		return time.Time{}, errors.New("ntp timestamp out of range")
	}
	return time.Unix(int64(secs)-ntpEpochOffset, 0).UTC(), nil
}
