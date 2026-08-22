package securefile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var (
	errInvalidPath    = errors.New("secure file path is invalid")
	errUnsafeFile     = errors.New("secure file permissions or type are unsafe")
	errReadFailed     = errors.New("secure file could not be read")
	errInvalidContent = errors.New("secure file content is invalid")
)

func ReadExact(path string, expectedBytes int) ([]byte, error) {
	if expectedBytes <= 0 {
		return nil, errInvalidContent
	}
	contents, err := readPrivateRegularFile(path, expectedBytes)
	if err != nil {
		return nil, err
	}
	if len(contents) != expectedBytes {
		return nil, errInvalidContent
	}
	return append([]byte(nil), contents...), nil
}

func ReadText(path string, maximumBytes int) (string, error) {
	if maximumBytes <= 0 {
		return "", errInvalidContent
	}
	contents, err := readPrivateRegularFile(path, maximumBytes)
	if err != nil {
		return "", err
	}
	if len(contents) == 0 || !utf8.Valid(contents) || bytes.IndexAny(contents, "\x00\r\n") >= 0 || strings.TrimSpace(string(contents)) == "" {
		return "", errInvalidContent
	}
	return string(contents), nil
}

func ReadBytes(path string, maximumBytes int) ([]byte, error) {
	if maximumBytes <= 0 {
		return nil, errInvalidContent
	}
	contents, err := readPrivateRegularFile(path, maximumBytes)
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, errInvalidContent
	}
	return append([]byte(nil), contents...), nil
}

func readPrivateRegularFile(path string, maximumBytes int) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalidPath
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errReadFailed
	}
	if !safeFileInfo(before) {
		return nil, errUnsafeFile
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, errReadFailed
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, errReadFailed
	}
	if !safeFileInfo(after) || !os.SameFile(before, after) {
		return nil, errUnsafeFile
	}

	contents, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil {
		return nil, errReadFailed
	}
	if len(contents) > maximumBytes {
		return nil, errInvalidContent
	}
	return contents, nil
}

func safeFileInfo(info os.FileInfo) bool {
	permissions := info.Mode().Perm()
	return info.Mode().IsRegular() && permissions&0o400 != 0 && permissions&0o177 == 0
}
