//go:build with_ech

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"strings"

	cftls "github.com/sagernet/cloudflare-tls"
	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-dns"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/ntp"

	mDNS "github.com/miekg/dns"
)

type echClientConfig struct {
	config *cftls.Config
}

func (c *echClientConfig) ServerName() string {
	return c.config.ServerName
}

func (c *echClientConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *echClientConfig) NextProtos() []string {
	return c.config.NextProtos
}

func (c *echClientConfig) SetNextProtos(nextProto []string) {
	c.config.NextProtos = nextProto
}

func (c *echClientConfig) Config() (*STDConfig, error) {
	return nil, E.New("unsupported usage for ECH")
}

func (c *echClientConfig) Client(conn net.Conn) (Conn, error) {
	return &echConnWrapper{cftls.Client(conn, c.config)}, nil
}

func (c *echClientConfig) Clone() Config {
	return &echClientConfig{
		config: c.config.Clone(),
	}
}

type echConnWrapper struct {
	*cftls.Conn
}

func (c *echConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *echConnWrapper) Upstream() any {
	return c.Conn
}

func NewECHClient(ctx context.Context, serverAddress string, yousuocanshu option.OutboundTLSOptions) (Config, error) {
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

	var tlsConfig cftls.Config
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
		tlsConfig.VerifyConnection = func(state cftls.ConnectionState) error {
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
			for _, tlsCipherSuite := range cftls.CipherSuites() {
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

	// ECH Config

	tlsConfig.ECHEnabled = true
	tlsConfig.PQSignatureSchemesEnabled = yousuocanshu.ECH.PQSignatureSchemesEnabled
	tlsConfig.DynamicRecordSizingDisabled = yousuocanshu.ECH.DynamicRecordSizingDisabled

	var echConfig []byte
	if len(yousuocanshu.ECH.Config) > 0 {
		echConfig = []byte(strings.Join(yousuocanshu.ECH.Config, "\n"))
	} else if yousuocanshu.ECH.ConfigPath != "" {
		content, err := os.ReadFile(yousuocanshu.ECH.ConfigPath)
		if err != nil {
			return nil, E.Cause(err, "read ECH config")
		}
		echConfig = content
	}

	if len(echConfig) > 0 {
		block, rest := pem.Decode(echConfig)
		if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
			return nil, E.New("invalid ECH configs pem")
		}
		echConfigs, err := cftls.UnmarshalECHConfigs(block.Bytes)
		if err != nil {
			return nil, E.Cause(err, "parse ECH configs")
		}
		tlsConfig.ClientECHConfigs = echConfigs
	} else {
		tlsConfig.GetClientECHConfigs = fetchECHClientConfig(ctx)
	}
	return &echClientConfig{&tlsConfig}, nil
}

func fetchECHClientConfig(ctx context.Context) func(_ context.Context, serverName string) ([]cftls.ECHConfig, error) {
	return func(_ context.Context, serverName string) ([]cftls.ECHConfig, error) {
		message := &mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				RecursionDesired: true,
			},
			Question: []mDNS.Question{
				{
					Name:   serverName + ".",
					Qtype:  mDNS.TypeHTTPS,
					Qclass: mDNS.ClassINET,
				},
			},
		}
		response, err := adapter.RouterFromContext(ctx).Exchange(ctx, message)
		if err != nil {
			return nil, err
		}
		if response.Rcode != mDNS.RcodeSuccess {
			return nil, dns.RCodeError(response.Rcode)
		}
		for _, rr := range response.Answer {
			switch resource := rr.(type) {
			case *mDNS.HTTPS:
				for _, value := range resource.Value {
					if value.Key().String() == "ech" {
						echConfig, err := base64.StdEncoding.DecodeString(value.String())
						if err != nil {
							return nil, E.Cause(err, "decode ECH config")
						}
						return cftls.UnmarshalECHConfigs(echConfig)
					}
				}
			default:
				return nil, E.New("unknown resource record type: ", resource.Header().Rrtype)
			}
		}
		return nil, E.New("no ECH config found")
	}
}
