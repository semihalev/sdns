package resolver

import (
	"fmt"
	"testing"
)

func BenchmarkBufferPool(b *testing.B) {
	sizes := []uint16{512, 1232, 4096, 65535}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					buf := AcquireBuf(size)
					// Simulate some work
					for i := 0; i < int(size); i += 100 {
						buf[i] = byte(i)
					}
					ReleaseBuf(buf)
				}
			})
		})
	}
}

func BenchmarkBufferPoolVsAlloc(b *testing.B) {
	b.Run("Pool_Mixed_Sizes", func(b *testing.B) {
		b.ReportAllocs()
		sizes := []uint16{512, 1232, 512, 4096, 512, 1232, 512}
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				size := sizes[i%len(sizes)]
				buf := AcquireBuf(size)
				buf[0] = 1
				buf[size-1] = 2
				ReleaseBuf(buf)
				i++
			}
		})
	})

	b.Run("Alloc_Mixed_Sizes", func(b *testing.B) {
		b.ReportAllocs()
		sizes := []uint16{512, 1232, 512, 4096, 512, 1232, 512}
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				size := sizes[i%len(sizes)]
				buf := make([]byte, size)
				buf[0] = 1
				buf[size-1] = 2
				i++
			}
		})
	})
}
