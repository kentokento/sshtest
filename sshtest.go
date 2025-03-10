package sshtest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var bitSize int = 2048

// Server is the SSH serving thing.
type Server struct {
	privKey ssh.Signer
	config  *ssh.ServerConfig

	Addr string
	Port int

	listener net.Listener

	handlers map[string]HandleFunc

	closed bool
	closeC chan interface{}
	mu     sync.Mutex
	wg     sync.WaitGroup
}

// HnadleFunc is a handler of the sshtest server. Needs to be registered for a
// command (see RegisterHandler).
type HandleFunc func(cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) (rVal int)

// NewServer starts the sshtest server.
func NewServer(opts ...Option) (*Server, error) {
	sCfg, err := newSSHCfg(opts)
	if err != nil {
		return nil, err
	}

	ss := new(Server)
	ss.Addr = sCfg.addr
	ss.Port = sCfg.port
	ss.config = sCfg.sc

	ss.handlers = make(map[string]HandleFunc)

	ss.closed = false
	ss.closeC = make(chan interface{})

	privKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate RSA key")
	}
	ss.privKey, err = ssh.NewSignerFromKey(privKey)
	ss.config.AddHostKey(ss.privKey)
	return ss, errors.Wrap(err, "failed to generate SSH signer from raw key")
}

// RegisterHandler will invoke the given function if the first field of the
// command to be executed matches the `cmd` string.
func (ss *Server) RegisterHandler(cmd string, f HandleFunc) {
	ss.handlers[cmd] = f
}

// Use this function with your client to check the servers host key.
func (ss *Server) CheckHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if bytes.Equal(key.Marshal(), ss.privKey.PublicKey().Marshal()) {
		return nil
	}
	return errors.Errorf("key didn't match")
}

// Close the server.
func (ss *Server) Close() error {
	log.Printf("closing test server")
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.closed = true
	close(ss.closeC)
	err := ss.listener.Close()
	ss.wg.Wait()
	log.Printf("closing test server: ...and done")
	return errors.Wrap(err, "failed to close listener")
}

// Listen starts a SSH server listens on given port.
func (ss *Server) Start() error {
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ss.Addr, ss.Port))
	if err != nil {
		return errors.Wrap(err, "failed to start listener")
	}
	ss.listener = l
	go ss.listen()
	return nil
}

func (ss *Server) listen() {
	ss.wg.Add(1)
	defer ss.wg.Done()

	for !ss.closed {
		conn, err := ss.listener.Accept()
		if err != nil {
			if !ss.closed {
				log.Printf("failed to accept from listener: %s", err)
			}
			continue
		}

		sConn, chans, reqs, err := ssh.NewServerConn(conn, ss.config)
		if err != nil {
			log.Printf("failed to create connection: %s", err)
			continue
		}

		go ssh.DiscardRequests(reqs)
		go ss.handleServerConn(sConn, chans)
	}

	log.Printf("closed listener loop")
}

func (ss *Server) handleServerConn(sConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	ss.wg.Add(1)
	defer ss.wg.Done()

	for {
		log.Printf("waiting for next channel")
		select {
		case nChan := <-chans:
			log.Printf("received channel")
			if err := ss.handleChannel(nChan); err != nil {
				log.Printf("ERR: %s", err)
			}
		case <-ss.closeC:
			log.Printf("closed channel loop")
			if err := sConn.Close(); err != nil {
				log.Printf("failed to close server conn: %s", err)
			}
			return
		}
	}
}

func (ss *Server) handleChannel(newChan ssh.NewChannel) error {
	if newChan.ChannelType() != "session" {
		err := newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		return errors.Wrap(err, "failed to reject new channel")
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		return errors.Wrap(err, "failed to accept from channel")
	}

	go func(ch ssh.Channel, in <-chan *ssh.Request) {
		ss.wg.Add(1)
		defer ss.wg.Done()

		for req := range in {
			switch req.Type {
			case "exec":
				var rVal int = 255
				parts := strings.Fields(string(req.Payload[4:]))
				cmd := parts[0]
				args := parts[1:]
				log.Printf("received command %q %d", cmd, len(req.Payload))
				if h, found := ss.handlers[cmd]; found {
					log.Printf("found command handler")
					sendReplyIfWanted(req, true, nil)
					rVal = h(cmd, args, ch, ch, ch.Stderr())
				} else {
					log.Printf("no command handler found")
					sendReplyIfWanted(req, false, []byte("command not found"))
				}

				if _, err := ch.SendRequest("exit-status", false, []byte{0, 0, 0, byte(rVal)}); err != nil {
					log.Printf("failed to send exit-status request")
				}
				if err := ch.Close(); err != nil {
					log.Printf("failed to close channel: %s", err)
				}
			default:
				req.Reply(false, []byte(""))
				log.Printf("unknown request type: %s", req.Type)
			}
		}
		log.Printf("closed channel")
	}(ch, reqs)
	return nil
}

func sendReplyIfWanted(req *ssh.Request, ok bool, payload []byte) {
	if req.WantReply {
		if err := req.Reply(ok, payload); err != nil {
			log.Printf("failed to send reply: %s", err)
		}
	}
}
