// Package middleware provides the DNS query middleware pipeline used by
// sdns. Middlewares are Constructors that produce Handlers; they register
// into a Registry, which Setup compiles into an immutable Pipeline. Each
// incoming DNS query runs through the pipeline via a Chain.
package middleware
