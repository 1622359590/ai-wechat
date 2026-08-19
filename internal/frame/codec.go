// Package frame reads and writes the legacy four-byte big-endian wire frame.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrZeroLength    = errors.New("frame body is empty")
	ErrFrameTooLarge = errors.New("frame body exceeds limit")
	ErrTruncated     = errors.New("frame is truncated")
)

// Decoder reads exactly one frame at a time and retains no body buffer.
type Decoder struct {
	reader io.Reader
	max    uint32
}

func NewDecoder(reader io.Reader, maxBodyBytes uint32) *Decoder {
	return &Decoder{reader: reader, max: maxBodyBytes}
}

func (decoder *Decoder) Read() ([]byte, error) {
	header := make([]byte, 4)
	read, err := io.ReadFull(decoder.reader, header)
	if err != nil {
		if err == io.EOF && read == 0 {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%w: header: %v", ErrTruncated, err)
	}

	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return nil, ErrZeroLength
	}
	if length > decoder.max {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, decoder.max)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(decoder.reader, body); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrTruncated, err)
	}
	return body, nil
}

func Write(writer io.Writer, body []byte, maxBodyBytes uint32) error {
	if len(body) == 0 {
		return ErrZeroLength
	}
	if uint64(len(body)) > uint64(maxBodyBytes) {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(body), maxBodyBytes)
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if err := writeFull(writer, header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if err := writeFull(writer, body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

func writeFull(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}
