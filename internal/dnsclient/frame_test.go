package dnsclient

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

// framePair returns a connected loopback TCP pair; net.Pipe is avoided for
// the allocation test because its rendezvous machinery allocates.
func framePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		server, err = ln.Accept()
	}()
	client, cerr := net.Dial("tcp", ln.Addr().String())
	if cerr != nil {
		t.Fatal(cerr)
	}
	<-done
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestFrameRoundTrip(t *testing.T) {
	client, server := framePair(t)

	payload := []byte("\x12\x34frame payload with header-ish bytes")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := WriteFrameFrom(client, payload)
		if err != nil || n != FramePrefixLen+len(payload) {
			t.Errorf("WriteFrameFrom = %d, %v", n, err)
		}
	}()

	dst := make([]byte, 4096)
	n, err := ReadFrameInto(server, dst)
	if err != nil || n != len(payload) || string(dst[:n]) != string(payload) {
		t.Fatalf("ReadFrameInto = %d, %v", n, err)
	}
	wg.Wait()

	// Prefixed variant: payload sits after headroom in one buffer.
	buf := make([]byte, FramePrefixLen+len(payload))
	copy(buf[FramePrefixLen:], payload)
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := WriteFramePrefixed(client, buf, len(payload))
		if err != nil || n != FramePrefixLen+len(payload) {
			t.Errorf("WriteFramePrefixed = %d, %v", n, err)
		}
	}()
	n, err = ReadFrameInto(server, dst)
	if err != nil || n != len(payload) || string(dst[:n]) != string(payload) {
		t.Fatalf("ReadFrameInto(prefixed) = %d, %v", n, err)
	}
	wg.Wait()
}

func TestFrameZeroLengthAcceptedAtFrameLayer(t *testing.T) {
	client, server := framePair(t)
	go func() { _, _ = WriteFrameFrom(client, nil) }()
	dst := make([]byte, 16)
	n, err := ReadFrameInto(server, dst)
	if err != nil || n != 0 {
		t.Fatalf("zero-length frame = %d, %v; the message layer rejects, not the frame layer", n, err)
	}
}

func TestFrameShortBufferConsumesPrefix(t *testing.T) {
	client, server := framePair(t)
	go func() { _, _ = WriteFrameFrom(client, make([]byte, 100)) }()
	dst := make([]byte, 10)
	if _, err := ReadFrameInto(server, dst); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("err = %v, want io.ErrShortBuffer", err)
	}
	// The stream is desynchronized by design: the prefix was consumed and
	// the payload was not. The caller's contract is to discard the conn.
}

func TestFrameOversizeWriteRefused(t *testing.T) {
	client, _ := framePair(t)
	if _, err := WriteFrameFrom(client, make([]byte, 65536)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrameFrom oversize err = %v", err)
	}
	if _, err := WriteFramePrefixed(client, make([]byte, 70000), 65536); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFramePrefixed oversize err = %v", err)
	}
	if _, err := WriteFramePrefixed(client, make([]byte, 4), 10); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("WriteFramePrefixed short buf err = %v", err)
	}
}

// TestFramePrefixedAllocsNothing pins the strict-path property: an echo
// exchange through WriteFramePrefixed/ReadFrameInto with owned buffers
// allocates nothing on either side once warm.
func TestFramePrefixedAllocsNothing(t *testing.T) {
	client, server := framePair(t)

	const payloadLen = 512
	// Echo server with owned buffers, warm before measuring.
	stop := make(chan struct{})
	served := make(chan struct{})
	go func() {
		defer close(served)
		buf := make([]byte, FramePrefixLen+65535)
		for {
			n, err := ReadFrameInto(server, buf[FramePrefixLen:])
			if err != nil {
				return
			}
			if _, err := WriteFramePrefixed(server, buf, n); err != nil {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	out := make([]byte, FramePrefixLen+payloadLen)
	in := make([]byte, 65535)
	exchange := func() {
		if _, err := WriteFramePrefixed(client, out, payloadLen); err != nil {
			t.Fatal(err)
		}
		if n, err := ReadFrameInto(client, in); err != nil || n != payloadLen {
			t.Fatal(n, err)
		}
	}
	exchange() // warm both goroutines' paths

	allocs := testing.AllocsPerRun(100, exchange)
	close(stop)
	exchange() // release the echo loop's pending read
	<-served
	if allocs != 0 {
		t.Fatalf("prefixed frame exchange allocated %.1f times per round trip, want 0", allocs)
	}
}
