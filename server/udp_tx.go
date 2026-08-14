package server

// The worker's TX burst: the jobs whose replies are staged and not yet
// sent. It is a plain array on the worker's stack — no pool, no channel,
// no goroutine handoff — because the worker owns every job in it from the
// moment it takes it off the ready queue until the send releases it.
//
// The burst is what turns one syscall per reply into one syscall per
// arrival group under load, and it is bounded so a worker can never hold
// more of the job ring than the ring was sized for.

// udpTXMax bounds a burst. It matches the receive batch, so a worker
// holds at most what one reader hands out.
const udpTXMax = udpBatchSize

type udpTXBurst struct {
	jobs [udpTXMax]*udpJob
	n    int
	// slot is the worker's index, which selects its send state. A worker
	// never shares that state, so the send needs no lock.
	slot int
}

func (b *udpTXBurst) add(j *udpJob) {
	b.jobs[b.n] = j
	b.n++
}

func (b *udpTXBurst) full() bool { return b.n == udpTXMax }

// release returns every job in the burst to the ring and empties it. The
// send has already happened (or failed) by the time this runs.
func (b *udpTXBurst) release() {
	for i := range b.n {
		j := b.jobs[i]
		b.jobs[i] = nil
		j.release(udpJobServing)
	}
	b.n = 0
}
