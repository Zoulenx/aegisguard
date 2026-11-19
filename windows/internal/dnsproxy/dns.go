package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aegisguard/windows/internal/filter"
)

const (
	TypeA    uint16 = 1
	TypeAAAA uint16 = 28
	ClassIN  uint16 = 1
)

type QueryEvent struct {
	Timestamp time.Time
	Domain    string
	Action    string
	Reason    string
	Client    string
}

type Server struct {
	ListenAddr string
	Upstreams  []string
	Filter     *filter.DomainFilter
	OnEvent    func(QueryEvent)

	mu            sync.Mutex
	conn          *net.UDPConn
	blockedCount  atomic.Uint64
	allowedCount  atomic.Uint64
	safeCount     atomic.Uint64
}

func NewServer(listenAddr string, df *filter.DomainFilter) *Server {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:53"
	}
	return &Server{
		ListenAddr: listenAddr,
		Upstreams: []string{
			"1.1.1.3:53",        // Cloudflare for Families (blocks malware + adult)
			"185.228.168.168:53", // CleanBrowsing Adult Filter
		},
		Filter: df,
	}
}

func (s *Server) Stats() (blocked, allowed, safesearch uint64) {
	return s.blockedCount.Load(), s.allowedCount.Load(), s.safeCount.Load()
}

func (s *Server) Start(ctx context.Context) (string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", s.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("invalid DNS listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return "", fmt.Errorf("failed binding DNS UDP socket %s: %w", s.ListenAddr, err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go s.serveLoop(ctx, conn)
	return conn.LocalAddr().String(), nil
}

func (s *Server) serveLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handlePacket(conn, clientAddr, packet)
	}
}

func (s *Server) handlePacket(conn *net.UDPConn, client *net.UDPAddr, req []byte) {
	qname, qtype, qEnd, err := ParseQuestion(req)
	if err != nil {
		return
	}

	decision := s.Filter.Evaluate(qname)
	switch decision.Action {
	case "BLOCK":
		s.blockedCount.Add(1)
		resp := BuildBlockedResponse(req, qtype, qEnd)
		_, _ = conn.WriteToUDP(resp, client)
		if s.OnEvent != nil {
			s.OnEvent(QueryEvent{
				Timestamp: time.Now().UTC(),
				Domain:    qname,
				Action:    "BLOCK",
				Reason:    decision.Reason,
				Client:    client.String(),
			})
		}
		return

	case "SAFESEARCH":
		s.safeCount.Add(1)
		if s.OnEvent != nil {
			s.OnEvent(QueryEvent{
				Timestamp: time.Now().UTC(),
				Domain:    qname,
				Action:    "SAFESEARCH",
				Reason:    decision.Reason,
				Client:    client.String(),
			})
		}
		// Forward rewritten SafeSearch query and rewrite QNAME back so the OS stub resolver accepts it.
		rewrittenReq := BuildQuery(binary.BigEndian.Uint16(req[0:2]), decision.SafeSearchHost, qtype)
		upResp, err := s.forwardUpstream(rewrittenReq)
		if err == nil && len(upResp) >= 12 {
			// Return a CNAME + SafeSearch answer, or forward direct A/AAAA answers extracted from upstream.
			patched := RewriteResponseQuestion(req, qEnd, upResp)
			_, _ = conn.WriteToUDP(patched, client)
			return
		}
		// Fallback to direct upstream if SafeSearch resolution failed.
	}

	s.allowedCount.Add(1)
	resp, err := s.forwardUpstream(req)
	if err != nil {
		servfail := BuildServFail(req)
		_, _ = conn.WriteToUDP(servfail, client)
		return
	}
	_, _ = conn.WriteToUDP(resp, client)
}

func (s *Server) forwardUpstream(req []byte) ([]byte, error) {
	var lastErr error
	for _, upstream := range s.Upstreams {
		d := net.Dialer{Timeout: 2500 * time.Millisecond}
		c, err := d.Dial("udp", upstream)
		if err != nil {
			lastErr = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(2500 * time.Millisecond))
		_, err = c.Write(req)
		if err != nil {
			_ = c.Close()
			lastErr = err
			continue
		}
		resp := make([]byte, 4096)
		n, err := c.Read(resp)
		_ = c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return resp[:n], nil
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}

// ParseQuestion parses the first DNS question from an RFC 1035 packet.
func ParseQuestion(packet []byte) (qname string, qtype uint16, questionEnd int, err error) {
	if len(packet) < 17 {
		return "", 0, 0, errors.New("dns packet too short")
	}
	qdcount := binary.BigEndian.Uint16(packet[4:6])
	if qdcount < 1 {
		return "", 0, 0, errors.New("no DNS question")
	}
	offset := 12
	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(packet) {
			return "", 0, 0, errors.New("invalid DNS label")
		}
		labels = append(labels, strings.ToLower(string(packet[offset:offset+length])))
		offset += length
	}
	if offset+4 > len(packet) {
		return "", 0, 0, errors.New("truncated DNS question")
	}
	qtype = binary.BigEndian.Uint16(packet[offset : offset+2])
	questionEnd = offset + 4
	return strings.Join(labels, "."), qtype, questionEnd, nil
}

// BuildBlockedResponse crafts an instant DNS block response (0.0.0.0 for A, :: for AAAA, NXDOMAIN otherwise).
func BuildBlockedResponse(req []byte, qtype uint16, questionEnd int) []byte {
	resp := make([]byte, 0, questionEnd+32)
	resp = append(resp, req[:questionEnd]...)
	// Standard response, recursion available
	if qtype == TypeA || qtype == TypeAAAA {
		resp[2] = 0x81
		resp[3] = 0x80 // NOERROR
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 1) // 1 answer
		binary.BigEndian.PutUint16(resp[8:10], 0)
		binary.BigEndian.PutUint16(resp[10:12], 0)

		// Pointer to QNAME at offset 12 (0xC00C)
		resp = append(resp, 0xC0, 0x0C)
		var meta [10]byte
		binary.BigEndian.PutUint16(meta[0:2], qtype)
		binary.BigEndian.PutUint16(meta[2:4], ClassIN)
		binary.BigEndian.PutUint32(meta[4:8], 60) // TTL 60s
		if qtype == TypeA {
			binary.BigEndian.PutUint16(meta[8:10], 4)
			resp = append(resp, meta[:]...)
			resp = append(resp, 0, 0, 0, 0)
		} else {
			binary.BigEndian.PutUint16(meta[8:10], 16)
			resp = append(resp, meta[:]...)
			resp = append(resp, make([]byte, 16)...)
		}
		return resp
	}

	// NXDOMAIN for non-A/AAAA records (including HTTPS/SVCB records used by modern browsers)
	resp[2] = 0x81
	resp[3] = 0x83 // NXDOMAIN
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func BuildServFail(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	resp := make([]byte, len(req))
	copy(resp, req)
	resp[2] = 0x81
	resp[3] = 0x82 // SERVFAIL
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func BuildQuery(txID uint16, domain string, qtype uint16) []byte {
	pkt := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(pkt[0:2], txID)
	pkt[2] = 0x01 // RD=1
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if label == "" {
			continue
		}
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], ClassIN)
	pkt = append(pkt, tail[:]...)
	return pkt
}

// RewriteResponseQuestion extracts A/AAAA records from the SafeSearch upstream answer and binds them to the original QNAME.
func RewriteResponseQuestion(origReq []byte, origQEnd int, upResp []byte) []byte {
	_, _, upQEnd, err := ParseQuestion(upResp)
	if err != nil {
		return upResp
	}
	ancount := binary.BigEndian.Uint16(upResp[6:8])
	if ancount == 0 {
		return upResp
	}

	out := make([]byte, 0, len(upResp)+32)
	out = append(out, origReq[:origQEnd]...)
	out[2] = 0x81
	out[3] = 0x80
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)

	offset := upQEnd
	written := uint16(0)
	for i := uint16(0); i < ancount && offset < len(upResp); i++ {
		// Skip answer NAME (pointer or labels)
		if upResp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(upResp) && upResp[offset] != 0 {
				offset += int(upResp[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(upResp) {
			break
		}
		rtype := binary.BigEndian.Uint16(upResp[offset : offset+2])
		rclass := binary.BigEndian.Uint16(upResp[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(upResp[offset+4 : offset+8])
		rdlen := int(binary.BigEndian.Uint16(upResp[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(upResp) {
			break
		}
		rdata := upResp[offset : offset+rdlen]
		offset += rdlen

		if rtype == TypeA || rtype == TypeAAAA {
			out = append(out, 0xC0, 0x0C) // pointer to original QNAME
			var hdr [10]byte
			binary.BigEndian.PutUint16(hdr[0:2], rtype)
			binary.BigEndian.PutUint16(hdr[2:4], rclass)
			binary.BigEndian.PutUint32(hdr[4:8], ttl)
			binary.BigEndian.PutUint16(hdr[8:10], uint16(rdlen))
			out = append(out, hdr[:]...)
			out = append(out, rdata...)
			written++
		}
	}
	if written == 0 {
		return upResp
	}
	binary.BigEndian.PutUint16(out[6:8], written)
	return out
}
