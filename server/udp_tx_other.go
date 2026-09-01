//go:build !linux || !(amd64 || arm64)

package server

// Without the raw batch layer there is no sendmmsg: the burst still
// exists, it is what keeps a job owned from read to send, but each
// reply leaves on its own, exactly as the portable writer always sent
// it. This is every target the batch path is not built for, Linux on an
// unverified architecture included.

type udpTXSender struct{}

func newUDPTXSender(*udpTXSender) {}

func (e *udpEngine) flushTX(b *udpTXBurst) {
	for i := range b.n {
		b.jobs[i].sendDirect()
	}
	b.release()
}
