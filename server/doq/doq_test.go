package doq

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

type dummyHandler struct{}

type doqContextKeyType struct{}

type contextAwareHandler struct {
	got any
}

func (h *contextAwareHandler) ServeMsg(ctx context.Context, w middleware.Transport, req *dns.Msg) {
	h.got = ctx.Value(doqContextKeyType{})
	resp := new(dns.Msg)
	resp.SetReply(req)
	_ = w.WriteMsg(resp)
}

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func (h *dummyHandler) ServeMsg(_ context.Context, w middleware.Transport, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Answer = append(msg.Answer, makeRR("example.com.		1800	IN	A	0.0.0.0"))

	_ = w.WriteMsg(msg)
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv any) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func generateCertificate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 3),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, "localhost")

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(filepath.Join(os.TempDir(), "test.cert"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	_ = certOut.Close() //nolint:gosec // G104 - test file cleanup

	keyOut, err := os.OpenFile(filepath.Join(os.TempDir(), "test.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) //nolint:gosec // G302 - secure permissions for private key
	if err != nil {
		return err
	}

	err = pem.Encode(keyOut, pemBlockForKey(priv))
	if err != nil {
		return err
	}

	return keyOut.Close()
}

func Test_doq(t *testing.T) {
	err := generateCertificate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	cert := filepath.Join(os.TempDir(), "test.cert")
	privkey := filepath.Join(os.TempDir(), "test.key")

	h := &dummyHandler{}

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := packet.LocalAddr().String()
	if err := packet.Close(); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Addr:    addr,
		Handler: h,
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	go func() {
		err := s.ListenAndServeQUIC(cert, privkey)
		if err == quic.ErrServerClosed {
			return
		}
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}()

	time.Sleep(time.Second)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402 - test client connecting to test server
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 0

	buf, err := req.Pack()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	n, err := stream.Write(addPrefixLen(buf))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n <= 17 {
		t.Errorf("n = %v, want > %v", n, 17)
	}

	err = stream.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	data, err := io.ReadAll(stream)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg := new(dns.Msg)
	err = msg.Unpack(data[2:])
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	stream, err = conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	time.Sleep(6 * time.Second)

	_, err = stream.Write([]byte{0, 0})
	if err == nil {
		t.Errorf("expected an error, got nil")
	}

	conn, err = quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	stream, err = conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = stream.Write([]byte{0, 0})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = stream.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = io.ReadAll(stream)
	if err == nil {
		t.Errorf("expected an error, got nil")
	}

	conn, err = quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	stream, err = conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg = new(dns.Msg)
	msg.SetEdns0(512, true)
	buf, _ = msg.Pack()

	_, err = stream.Write(buf)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = stream.Close()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = io.ReadAll(stream)
	if err == nil {
		t.Errorf("expected an error, got nil")
	}

	err = s.Shutdown()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServerDispatchesStreamContextToAwareHandler(t *testing.T) {
	handler := new(contextAwareHandler)
	s := &Server{Handler: handler}
	req := new(dns.Msg)
	req.SetQuestion("context.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	ctx := context.WithValue(context.Background(), doqContextKeyType{}, "stream")

	s.Handler.ServeMsg(ctx, writer, req)

	if handler.got != "stream" {
		t.Fatalf("handler context value = %v, want stream", handler.got)
	}
	if !writer.Written() || writer.Msg().Rcode != dns.RcodeSuccess {
		t.Fatalf("handler response = %#v, want NOERROR", writer.Msg())
	}
}
