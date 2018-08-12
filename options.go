package sshtest

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type sshCfg struct {
	sc   *ssh.ServerConfig
	addr string
	port int
}

func newSSHCfg(opts []Option) (*sshCfg, error) {
	cfg := &sshCfg{addr: "127.0.90.22", port: 22022}
	cfg.sc = new(ssh.ServerConfig)

	return cfg, cfg.ApplyOpts(opts)
}

func (sc *sshCfg) ApplyOpts(opts []Option) error {
	for i := range opts {
		if err := opts[i](sc); err != nil {
			return err
		}
	}
	return nil
}

// Option is used to modify the ssh server behavior.
type Option func(*sshCfg) error

// WithAddr sets the address of the test ssh server.
func WithAddr(addr string) Option {
	return func(cfg *sshCfg) error {
		cfg.addr = addr
		return nil
	}
}

// WithPort changes the port from the default of 22.
func WithPort(port int) Option {
	return func(cfg *sshCfg) error {
		cfg.port = port
		return nil
	}
}

// WithPublicKeyCallback sets a callback used to authenticate a user via a
// public key.
func WithPublicKeyCallback(f func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)) Option {
	return func(cfg *sshCfg) error {
		cfg.sc.PublicKeyCallback = f
		return nil
	}
}

// WithPasswordCallback sets a callback used to test a user supplied password.
func WithPasswordCallback(f func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error)) Option {
	return func(cfg *sshCfg) error {
		cfg.sc.PasswordCallback = f
		return nil
	}
}

// WithPasswordCallbackForUser sets a callback that grants the given user with
// the given password access.
func WithPasswordCallbackForUser(user, password string) Option {
	return func(cfg *sshCfg) error {
		cfg.sc.PasswordCallback = func(conn ssh.ConnMetadata, secret []byte) (*ssh.Permissions, error) {
			if conn.User() != user || string(secret) != password {
				return nil, errors.Errorf("username or password don't match")
			}
			return new(ssh.Permissions), nil
		}
		return nil
	}
}
