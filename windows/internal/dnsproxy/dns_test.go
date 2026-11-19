package dnsproxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"aegisguard/windows/internal/filter"
	"aegisguard/windows/internal/rules"
)

func TestDNSServerBlocksAdultAndRewritesSafeSearch(t *testing.T) {
	// Spin up a mock upstream UDP DNS server locally so tests run 100% offline.
	mockUp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed mock upstream: %v", err)
	}
	defer mockUp.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := mockUp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			qname, qtype, qEnd, err := ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			resp := make([]byte, 0, qEnd+16)
			resp = append(resp, buf[:qEnd]...)
			resp[2] = 0x81
			resp[3] = 0x80
			binary.BigEndian.PutUint16(resp[4:6], 1)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0xC0, 0x0C)
			var hdr [10]byte
			binary.BigEndian.PutUint16(hdr[0:2], qtype)
			binary.BigEndian.PutUint16(hdr[2:4], ClassIN)
			binary.BigEndian.PutUint32(hdr[4:8], 300)
			binary.BigEndian.PutUint16(hdr[8:10], 4)
			resp = append(resp, hdr[:]...)
			if qname == "forcesafesearch.google.com" {
				resp = append(resp, 216, 239, 38, 120) // Official Google SafeSearch VIP
			} else {
				resp = append(resp, 93, 184, 216, 34)
			}
			_, _ = mockUp.WriteToUDP(resp, addr)
		}
	}()

	domains, _ := rules.LoadEmbeddedBlocklist()
	kr, _ := rules.LoadEmbeddedKeywords()
	sr, _ := rules.LoadEmbeddedSocialApps()
	df := filter.NewDomainFilter(domains, sr, filter.NewSemanticFilter(kr))

	srv := NewServer("127.0.0.1:0", df)
	srv.Upstreams = []string{mockUp.LocalAddr().String()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr, err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("failed starting DNS server: %v", err)
	}

	sendQuery := func(domain string) []byte {
		c, err := net.DialTimeout("udp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		q := BuildQuery(0x1234, domain, TypeA)
		_, _ = c.Write(q)
		resp := make([]byte, 512)
		n, err := c.Read(resp)
		if err != nil {
			t.Fatalf("read failed for %s: %v", domain, err)
		}
		return resp[:n]
	}

	// 1. Blocked domain -> 0.0.0.0
	resp := sendQuery("pornhub.com")
	ip := net.IP(resp[len(resp)-4:])
	if ip.String() != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0 for pornhub.com, got %s", ip.String())
	}

	// 2. SafeSearch domain -> 216.239.38.120
	resp = sendQuery("www.google.com")
	ip = net.IP(resp[len(resp)-4:])
	if ip.String() != "216.239.38.120" {
		t.Fatalf("expected SafeSearch IP 216.239.38.120 for www.google.com, got %s", ip.String())
	}

	// 3. Normal domain -> forwarded mock IP
	resp = sendQuery("example.com")
	ip = net.IP(resp[len(resp)-4:])
	if ip.String() != "93.184.216.34" {
		t.Fatalf("expected 93.184.216.34 for example.com, got %s", ip.String())
	}
}
