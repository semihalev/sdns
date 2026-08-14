//go:build !linux

package server

// Off Linux there is no sendmmsg: the burst still exists — it is what
// keeps a job owned from read to send — but each reply leaves on its own,
// exactly as the portable writer always sent it.

type udpTXSender struct{}

func newUDPTXSender(*udpTXSender) {}

func (e *udpEngine) flushTX(b *udpTXBurst) {
	for i := range b.n {
		b.jobs[i].sendDirect()
	}
	b.release()
}
