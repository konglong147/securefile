package sniff

import (
	"context"
	"encoding/binary"
	"io"
	"os"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/local/sing/common/rw"
)

func RDP(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var tpktVersion uint8
	err := binary.Read(reader, binary.BigEndian, &tpktVersion)
	if err != nil {
		return err
	}
	if tpktVersion != 0x03 {
		return os.ErrInvalid
	}

	var tpktReserved uint8
	err = binary.Read(reader, binary.BigEndian, &tpktReserved)
	if err != nil {
		return err
	}
	if tpktReserved != 0x00 {
		return os.ErrInvalid
	}

	var tpktLength uint16
	err = binary.Read(reader, binary.BigEndian, &tpktLength)
	if err != nil {
		return err
	}

	if tpktLength != 19 {
		return os.ErrInvalid
	}

	var cotpLength uint8
	err = binary.Read(reader, binary.BigEndian, &cotpLength)
	if err != nil {
		return err
	}

	if cotpLength != 14 {
		return os.ErrInvalid
	}

	var cotpTpduType uint8
	err = binary.Read(reader, binary.BigEndian, &cotpTpduType)
	if err != nil {
		return err
	}
	if cotpTpduType != 0xE0 {
		return os.ErrInvalid
	}

	err = rw.SkipN(reader, 5)
	if err != nil {
		return err
	}

	var rdpType uint8
	err = binary.Read(reader, binary.BigEndian, &rdpType)
	if err != nil {
		return err
	}
	if rdpType != 0x01 {
		return os.ErrInvalid
	}
	var rdpFlags uint8
	err = binary.Read(reader, binary.BigEndian, &rdpFlags)
	if err != nil {
		return err
	}
	var rdpLength uint8
	err = binary.Read(reader, binary.BigEndian, &rdpLength)
	if err != nil {
		return err
	}
	if rdpLength != 8 {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolRDP
	return nil
}
