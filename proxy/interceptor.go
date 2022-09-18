package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/kardianos/mitmproxy/cert"
	log "github.com/sirupsen/logrus"
)

// Similar to standard library server, run through current process memory socket data, without tcp or unix socket.

type pipeAddr struct {
	remoteAddr string
}

func (pipeAddr) Network() string   { return "pipe" }
func (a *pipeAddr) String() string { return a.remoteAddr }

// add Peek method for conn
type pipeConn struct {
	net.Conn
	r           *bufio.Reader
	host        string // server host:port
	remoteAddr  string // client ip:port
	connContext *ConnContext
}

func newPipeConn(c net.Conn, req *http.Request) *pipeConn {
	connContext := req.Context().Value(connContextKey).(*ConnContext)
	pipeConn := &pipeConn{
		Conn:        c,
		r:           bufio.NewReader(c),
		host:        req.Host,
		remoteAddr:  req.RemoteAddr,
		connContext: connContext,
	}
	connContext.pipeConn = pipeConn
	return pipeConn
}

func (c *pipeConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *pipeConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *pipeConn) RemoteAddr() net.Addr {
	return &pipeAddr{remoteAddr: c.remoteAddr}
}

// Setup client and server communication.
func newPipes(req *http.Request) (net.Conn, *pipeConn) {
	client, srv := net.Pipe()
	server := newPipeConn(srv, req)
	return client, server
}

// mock net.Listener
type middleListener struct {
	connChan chan net.Conn
	doneChan chan struct{}
}

func (l *middleListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connChan:
		return c, nil
	case <-l.doneChan:
		return nil, http.ErrServerClosed
	}
}
func (l *middleListener) Close() error   { return nil }
func (l *middleListener) Addr() net.Addr { return nil }

// middle: man-in-the-middle server
type middle struct {
	proxy    *Proxy
	ca       cert.Getter
	listener *middleListener
	server   *http.Server
}

func newMiddle(proxy *Proxy) (*middle, error) {
	m := &middle{
		proxy: proxy,
		ca:    proxy.Opts.CA,
		listener: &middleListener{
			connChan: make(chan net.Conn),
			doneChan: make(chan struct{}),
		},
	}

	server := &http.Server{
		Handler: m,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*tls.Conn).NetConn().(*pipeConn).connContext)
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // Disable http2.
		TLSConfig: &tls.Config{
			SessionTicketsDisabled: true, // Set to true, ensure GetCertificate is always called.
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				connCtx := clientHello.Context().Value(connContextKey).(*ConnContext)
				if err := connCtx.tlsHandshake(clientHello); err != nil {
					return nil, err
				}

				for _, addon := range connCtx.proxy.Addons {
					addon.TlsEstablishedServer(connCtx)
				}

				return m.ca.GetCert(clientHello.ServerName)
			},
		},
	}
	m.server = server
	return m, nil
}

func (m *middle) start() error {
	return m.server.ServeTLS(m.listener, "", "")
}

func (m *middle) close() error {
	err := m.server.Close()
	close(m.listener.doneChan)
	return err
}

func (m *middle) dial(req *http.Request) (net.Conn, error) {
	pipeClientConn, pipeServerConn := newPipes(req)
	err := pipeServerConn.connContext.initServerTcpConn(req)
	if err != nil {
		pipeClientConn.Close()
		pipeServerConn.Close()
		return nil, err
	}
	go m.intercept(pipeServerConn)
	return pipeClientConn, nil
}

func (m *middle) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		// wss
		defaultWebSocket.wss(res, req)
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	m.proxy.ServeHTTP(res, req)
}

// Parse connect flow.
// In case of tls flow, listener.Accept => Middle.ServeHTTP
// Otherwise assume ws flow.
func (m *middle) intercept(pipeServerConn *pipeConn) {
	buf, err := pipeServerConn.Peek(3)
	if err != nil {
		log.Errorf("Peek error: %v\n", err)
		pipeServerConn.Close()
		return
	}

	// https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py is_tls_record_magic
	if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03 {
		// tls
		pipeServerConn.connContext.ClientConn.TLS = true
		pipeServerConn.connContext.initHttpsServerConn()
		m.listener.connChan <- pipeServerConn
	} else {
		// ws
		defaultWebSocket.ws(pipeServerConn, pipeServerConn.host)
	}
}
