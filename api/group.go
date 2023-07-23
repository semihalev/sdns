package api

type Group struct {
	parent *Router
	path   string
}

func (g *Group) Handle(method, path string, handle Handler) {
	g.parent.Handle(method, g.path+path, handle)
}

func (g *Group) GET(path string, handle Handler) {
	g.parent.GET(g.path+path, handle)
}

func (g *Group) POST(path string, handle Handler) {
	g.parent.POST(g.path+path, handle)
}
