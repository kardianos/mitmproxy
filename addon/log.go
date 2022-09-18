package addon

import (
	"time"

	"github.com/kardianos/mitmproxy/proxy"

	log "github.com/sirupsen/logrus"
)

// LogAddon log connection and flow
type LogAddon struct {
	proxy.BaseAddon
}

func (addon *LogAddon) ClientConnected(client *proxy.ClientConn) {
	log.Infof("%v client connect\n", client.Conn.RemoteAddr())
}

func (addon *LogAddon) ClientDisconnected(client *proxy.ClientConn) {
	log.Infof("%v client disconnect\n", client.Conn.RemoteAddr())
}

func (addon *LogAddon) ServerConnected(connCtx *proxy.ConnContext) {
	log.Infof("%v server connect %v (%v->%v)\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr())
}

func (addon *LogAddon) ServerDisconnected(connCtx *proxy.ConnContext) {
	log.Infof("%v server disconnect %v (%v->%v)\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr())
}

func (addon *LogAddon) Requestheaders(f *proxy.Flow) {
	start := time.Now()
	go func() {
		<-f.Done()
		var StatusCode int
		if f.Response != nil {
			StatusCode = f.Response.StatusCode
		}
		var contentLen int
		if f.Response != nil && f.Response.Body != nil {
			contentLen = len(f.Response.Body)
		}
		log.Infof("%v %v %v %v %v - %v ms\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String(), StatusCode, contentLen, time.Since(start).Milliseconds())
	}()
}
