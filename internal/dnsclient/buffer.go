package dnsclient

import "sync"

// Size-bucketed buffer pools for efficient memory usage.
var bufferPools = [4]sync.Pool{
	{New: func() any { return new([512]byte) }},   // 0-512 bytes (most DNS over UDP)
	{New: func() any { return new([1232]byte) }},  // 513-1232 bytes (EDNS0 UDP)
	{New: func() any { return new([4096]byte) }},  // 1233-4096 bytes (typical TCP)
	{New: func() any { return new([65535]byte) }}, // 4097-65535 bytes (max DNS)
}

// AcquireBuf returns a buffer from the appropriate pool.
func AcquireBuf(size uint16) []byte {
	switch {
	case size <= 512:
		return bufferPools[0].Get().(*[512]byte)[:size]
	case size <= 1232:
		return bufferPools[1].Get().(*[1232]byte)[:size]
	case size <= 4096:
		return bufferPools[2].Get().(*[4096]byte)[:size]
	default:
		return bufferPools[3].Get().(*[65535]byte)[:size]
	}
}

// ReleaseBuf returns buf to the appropriate pool.
func ReleaseBuf(buf []byte) {
	switch cap(buf) {
	case 512:
		bufferPools[0].Put((*[512]byte)(buf[:512]))
	case 1232:
		bufferPools[1].Put((*[1232]byte)(buf[:1232]))
	case 4096:
		bufferPools[2].Put((*[4096]byte)(buf[:4096]))
	case 65535:
		bufferPools[3].Put((*[65535]byte)(buf[:65535]))
	default:
		// Buffer too large, let GC handle it
	}
}
