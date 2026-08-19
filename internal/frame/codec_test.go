package frame_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/1622359590/ai-wechat/internal/frame"
)

func TestDecoderReadsPartialAndConcatenatedFrames(t *testing.T) {
	first := encodedFrame([]byte("first"))
	second := encodedFrame([]byte("second"))
	decoder := frame.NewDecoder(&chunkReader{reader: bytes.NewReader(append(first, second...)), size: 1}, 32)

	for index, want := range [][]byte{[]byte("first"), []byte("second")} {
		got, err := decoder.Read()
		if err != nil {
			t.Fatalf("read frame %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d = %q, want %q", index, got, want)
		}
	}
	if _, err := decoder.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("final read error = %v, want EOF", err)
	}
}

func TestDecoderRejectsInvalidLengthsBeforeBodyRead(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		max  uint32
		want error
	}{
		{name: "zero", body: header(0), max: 32, want: frame.ErrZeroLength},
		{name: "oversized", body: append(header(33), bytes.Repeat([]byte{1}, 33)...), max: 32, want: frame.ErrFrameTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bytes.NewReader(test.body)
			_, err := frame.NewDecoder(reader, test.max).Read()
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if got, want := reader.Len(), len(test.body)-4; got != want {
				t.Fatalf("remaining bytes = %d, want %d", got, want)
			}
		})
	}
}

func TestDecoderReportsTruncatedHeaderAndBody(t *testing.T) {
	for _, input := range [][]byte{{0, 0}, append(header(4), 1, 2)} {
		_, err := frame.NewDecoder(bytes.NewReader(input), 32).Read()
		if !errors.Is(err, frame.ErrTruncated) {
			t.Fatalf("error = %v, want ErrTruncated", err)
		}
	}
}

func TestWriteHandlesShortWritesAndLimits(t *testing.T) {
	writer := &chunkWriter{size: 2}
	if err := frame.Write(writer, []byte("payload"), 32); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if got, want := writer.Bytes(), encodedFrame([]byte("payload")); !bytes.Equal(got, want) {
		t.Fatalf("encoded frame = %x, want %x", got, want)
	}
	if err := frame.Write(io.Discard, nil, 32); !errors.Is(err, frame.ErrZeroLength) {
		t.Fatalf("zero error = %v, want ErrZeroLength", err)
	}
	if err := frame.Write(io.Discard, bytes.Repeat([]byte{1}, 33), 32); !errors.Is(err, frame.ErrFrameTooLarge) {
		t.Fatalf("oversized error = %v, want ErrFrameTooLarge", err)
	}
}

func encodedFrame(body []byte) []byte {
	return append(header(uint32(len(body))), body...)
}

func header(length uint32) []byte {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, length)
	return value
}

type chunkReader struct {
	reader io.Reader
	size   int
}

func (reader *chunkReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.size {
		buffer = buffer[:reader.size]
	}
	return reader.reader.Read(buffer)
}

type chunkWriter struct {
	bytes.Buffer
	size int
}

func (writer *chunkWriter) Write(buffer []byte) (int, error) {
	if len(buffer) > writer.size {
		buffer = buffer[:writer.size]
	}
	return writer.Buffer.Write(buffer)
}
