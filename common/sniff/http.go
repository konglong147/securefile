package sniff

import (
	std_bufio "bufio"
	"context"
	"io"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	"github.com/konglong147/securefile/local/sing/protocol/http"
)

func HTTPHost(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	request, err := http.ReadRequest(std_bufio.NewReader(reader))
	if err != nil {
		return err
	}
	metadata.Protocol = C.ProtocolHTTP
	metadata.Domain = M.ParseSocksaddr(request.Host).AddrString()
	return nil
}
