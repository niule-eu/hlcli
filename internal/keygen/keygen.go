package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"

	"fmt"
	"io"
	"os"

	"github.com/niuleh/hlcli/internal/framework"
	"golang.org/x/crypto/ssh"
)

type KeyGen interface {
	Prepare() ([]framework.Effect, error)
}

type RSAKeyGen struct {
	Bits    int
	Comment string
	Output  string
}

func (rsap RSAKeyGen) Prepare() ([]framework.Effect, error) {
	f := func(io.Reader) ([]byte, []byte, error) {
		var _bits int
		switch rsap.Bits {
		case 2048:
			_bits = 2048
		case 4096:
			_bits = 4096
		default:
			println("keygen RSA: invalid bits, defaulting to 2048 bits")
			_bits = 2048
		}
		priv, err := rsa.GenerateKey(rand.Reader, _bits)
		if err != nil {
			return nil, nil, err
		}
		err = priv.Validate()
		if err != nil {
			return nil, nil, err
		}

		return _marshalKeyPair(priv, rsap.Comment)
	}
	return _makeKeyGenIOs(f, rsap.Output)
}

type ED25519KeyGen struct {
	Comment string
	Output  string
}

func (ed25519p ED25519KeyGen) Prepare() ([]framework.Effect, error) {
	f := func(io.Reader) ([]byte, []byte, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		return _marshalKeyPair(priv, ed25519p.Comment)
	}
	return _makeKeyGenIOs(f, ed25519p.Output)
}

type ECDSAKeyGen struct {
	CurveBits int
	Comment   string
	Output    string
}

func (ecdsap ECDSAKeyGen) Prepare() ([]framework.Effect, error) {
	f := func(io.Reader) ([]byte, []byte, error) {
		var curve elliptic.Curve
		switch ecdsap.CurveBits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P384()
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return _marshalKeyPair(priv, ecdsap.Comment)
	}
	return _makeKeyGenIOs(f, ecdsap.Output)
}

func _marshalKeyPair(key interface{}, comment string) ([]byte, []byte, error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		priv_pem, err := ssh.MarshalPrivateKey(key, comment)
		if err != nil {
			return nil, nil, err
		}
		pub_key, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return ssh.MarshalAuthorizedKey(pub_key), pem.EncodeToMemory(priv_pem), nil
	case *ecdsa.PrivateKey:
		priv_pem, err := ssh.MarshalPrivateKey(key, comment)
		if err != nil {
			return nil, nil, err
		}
		pub_key, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return ssh.MarshalAuthorizedKey(pub_key), pem.EncodeToMemory(priv_pem), nil
	case ed25519.PrivateKey:
		priv_pem, err := ssh.MarshalPrivateKey(key, comment)
		if err != nil {
			return nil, nil, err
		}
		pub_key, err := ssh.NewPublicKey(key.Public())
		if err != nil {
			return nil, nil, err
		}
		return ssh.MarshalAuthorizedKey(pub_key), pem.EncodeToMemory(priv_pem), nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

func _makeKeyGenIOs(f func(io.Reader) ([]byte, []byte, error), output string) ([]framework.Effect, error) {
	pub_bytes, priv_bytes, err := f(rand.Reader)
	if err != nil {
		return nil, err
	}
	priv_io := framework.FileWriteIO{
		Path:        output,
		Content:     priv_bytes,
		Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		Permissions: 0644,
	}
	pub_io := framework.FileWriteIO{
		Path:        output + ".pub",
		Content:     pub_bytes,
		Mode:        os.O_CREATE | os.O_WRONLY | os.O_TRUNC,
		Permissions: 0644,
	}
	return []framework.Effect{&priv_io, &pub_io}, nil
}
