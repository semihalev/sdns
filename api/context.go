package api

import (
	"encoding/json"
	"net/http"
)

type (
	Context struct {
		Request *http.Request
		Writer  http.ResponseWriter
		Handler Handler
		Params  *Params
	}

	Handler func(ctx *Context)

	Param struct {
		Key   string
		Value string
	}

	Params []Param

	Json map[string]any
)

func (ctx *Context) JSON(code int, data any) {
	buf, err := json.Marshal(data)
	if err != nil {
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.Writer.WriteHeader(code)
	ctx.Writer.Header().Set("Content-Type", "application/json")

	_, _ = ctx.Writer.Write(buf)
}

func (ctx *Context) Param(key string) string {
	params := *ctx.Params
	for _, p := range params {
		if p.Key == key {
			return p.Value
		}
	}

	return ""
}

func (ctx *Context) addParameter(key, value string) {
	i := len(*ctx.Params)
	*ctx.Params = (*ctx.Params)[:i+1]
	(*ctx.Params)[i] = Param{
		Key:   key,
		Value: value,
	}
}
