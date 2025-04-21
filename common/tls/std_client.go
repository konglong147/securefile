package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/konglong147/securefile/option"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/ntp"
)

type STDClientConfig struct {
	config *tls.Config
}

func (s *STDClientConfig) ServerName() string {
	return s.config.ServerName
}

func (s *STDClientConfig) SetServerName(serverName string) {
	s.config.ServerName = serverName
}

func (s *STDClientConfig) NextProtos() []string {
	return s.config.NextProtos
}

func (s *STDClientConfig) SetNextProtos(nextProto []string) {
	s.config.NextProtos = nextProto
}

func (s *STDClientConfig) Config() (*STDConfig, error) {
	return s.config, nil
}

func (s *STDClientConfig) Client(conn net.Conn) (Conn, error) {
	return tls.Client(conn, s.config), nil
}

func (s *STDClientConfig) Clone() Config {
	return &STDClientConfig{s.config.Clone()}
}

func NewSTDClient(ctx context.Context, serverAddress string, yousuocanshu option.OutboundTLSOptions) (Config, error) {
	var serverName string
	if yousuocanshu.ServerName != "" {
		serverName = yousuocanshu.ServerName
	} else if serverAddress != "" {
		if _, err := netip.ParseAddr(serverName); err != nil {
			serverName = serverAddress
		}
	}
	if serverName == "" && !yousuocanshu.Insecure {
		return nil, E.New("xiaoshidelixing server_name or insecure=true")
	}

	var tlsConfig tls.Config
	tlsConfig.Time = ntp.TimeFuncFromContext(ctx)
	if yousuocanshu.DisableSNI {
		tlsConfig.ServerName = "127.0.0.1"
	} else {
		tlsConfig.ServerName = serverName
	}
	if yousuocanshu.Insecure {
		tlsConfig.InsecureSkipVerify = yousuocanshu.Insecure
	} else if yousuocanshu.DisableSNI {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			verifyOptions := x509.VerifyOptions{
				DNSName:       serverName,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range state.PeerCertificates[1:] {
				verifyOptions.Intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(verifyOptions)
			return err
		}
	}
	if len(yousuocanshu.ALPN) > 0 {
		tlsConfig.NextProtos = yousuocanshu.ALPN
	}
	if yousuocanshu.MinVersion != "" {
		minVersion, err := ParseTLSVersion(yousuocanshu.MinVersion)
		if err != nil {
			return nil, E.Cause(err, "parse min_version")
		}
		tlsConfig.MinVersion = minVersion
	}
	if yousuocanshu.MaxVersion != "" {
		maxVersion, err := ParseTLSVersion(yousuocanshu.MaxVersion)
		if err != nil {
			return nil, E.Cause(err, "parse max_version")
		}
		tlsConfig.MaxVersion = maxVersion
	}
	if yousuocanshu.CipherSuites != nil {
	find:
		for _, cipherSuite := range yousuocanshu.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}
	var certificate []byte
	if len(yousuocanshu.Certificate) > 0 {
		certificate = []byte(strings.Join(yousuocanshu.Certificate, "\n"))
	} else if yousuocanshu.CertificatePath != "" {
		content, err := os.ReadFile(yousuocanshu.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, E.New("failed to parse certificate:\n\n", certificate)
		}
		tlsConfig.RootCAs = certPool
	}
	return &STDClientConfig{&tlsConfig}, nil
}
