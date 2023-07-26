package api

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"sync"

	"github.com/semihalev/log"
)

type Router struct {
	get     Tree
	post    Tree
	delete  Tree
	put     Tree
	patch   Tree
	head    Tree
	connect Tree
	trace   Tree
	options Tree

	ctxPool sync.Pool
}

var extraHeaders = map[string]string{
	"Server":                       "sdns",
	"Access-Control-Allow-Origin":  "*",
	"Access-Control-Allow-Methods": "GET,POST",
	"Cache-Control":                "no-cache, no-store, no-transform, must-revalidate, private, max-age=0",
	"Pragma":                       "no-cache",
}

func NewRouter() *Router {
	r := &Router{}

	r.ctxPool.New = func() any {
		params := make(Params, 0, 20)
		return &Context{Params: &params}
	}

	return r
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Error("Recovered in API", "recover", r)

			_, _ = os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
		}
	}()

	for k, v := range extraHeaders {
		w.Header().Set(k, v)
	}

	ctx := rt.getContext(w, r)

	if r.Method[0] == 'G' {
		rt.get.Lookup(ctx)
	} else {
		tree := rt.selectTree(r.Method)
		tree.Lookup(ctx)
	}

	if ctx.Handler == nil {
		http.NotFound(w, r)
		rt.putContext(ctx)
		return
	}

	ctx.Handler(ctx)

	rt.putContext(ctx)
}

func (rt *Router) Handle(method, path string, handle Handler) {
	tree := rt.selectTree(method)
	tree.Add(path, handle)
}

func (rt *Router) GET(path string, handle Handler) {
	rt.get.Add(path, handle)
}

func (rt *Router) POST(path string, handle Handler) {
	rt.post.Add(path, handle)
}

func (rt *Router) Group(rp string) *Group {
	return &Group{parent: rt, path: rp}
}

func (rt *Router) getContext(w http.ResponseWriter, r *http.Request) *Context {
	ctx := rt.ctxPool.Get().(*Context)

	ctx.Request = r
	ctx.Writer = w
	ctx.Handler = nil
	(*ctx.Params) = (*ctx.Params)[:0]

	return ctx
}

func (rt *Router) putContext(ctx *Context) {
	rt.ctxPool.Put(ctx)
}

func (rt *Router) selectTree(method string) *Tree {
	switch method {
	case http.MethodGet:
		return &rt.get
	case http.MethodPost:
		return &rt.post
	case http.MethodDelete:
		return &rt.delete
	case http.MethodPut:
		return &rt.put
	case http.MethodPatch:
		return &rt.patch
	case http.MethodHead:
		return &rt.head
	case http.MethodConnect:
		return &rt.connect
	case http.MethodTrace:
		return &rt.trace
	case http.MethodOptions:
		return &rt.options
	default:
		return nil
	}
}
