package server

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"
)

var (
	codexUDPJobSizeProbe    [unsafe.Sizeof(udpJob{})]byte
	codexTCPJobSizeProbe    [unsafe.Sizeof(tcpJob{})]byte
	codexTCPStreamSizeProbe [unsafe.Sizeof(tcpStream{})]byte
	codexUDPBurstSizeProbe  [unsafe.Sizeof(udpTXBurst{})]byte
	codexUDPSenderSizeProbe [unsafe.Sizeof(udpTXSender{})]byte
)

func TestCodexSizeProbe(t *testing.T) {
	t.Logf("goos=%s goarch=%s ptr=%d udpJob=%d tcpJob=%d tcpStream=%d udpBurst=%d udpSender=%d",
		runtime.GOOS, runtime.GOARCH, unsafe.Sizeof(uintptr(0)), unsafe.Sizeof(udpJob{}),
		unsafe.Sizeof(tcpJob{}), unsafe.Sizeof(tcpStream{}), unsafe.Sizeof(udpTXBurst{}),
		unsafe.Sizeof(udpTXSender{}))
	_ = fmt.Sprintf("%d/%d/%d/%d/%d", len(codexUDPJobSizeProbe), len(codexTCPJobSizeProbe),
		len(codexTCPStreamSizeProbe), len(codexUDPBurstSizeProbe), len(codexUDPSenderSizeProbe))
}
