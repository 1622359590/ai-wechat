// Package schema compiles and caches the embedded recovered protocol schema.
package schema

import (
	"context"
	"io"
	"sync"

	"github.com/1622359590/ai-wechat/proto/minimal"
	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

var sourceFiles = []string{
	"TransportMessage.proto",
	"DeviceAuthReq.proto",
	"HeartBeat.proto",
	"FriendTalkNotice.proto",
	"TalkToFriendTask.proto",
}

var (
	loadOnce sync.Once
	loaded   *protoregistry.Files
	loadErr  error
)

// Load returns one immutable registry shared by all callers.
func Load() (*protoregistry.Files, error) {
	loadOnce.Do(func() {
		loaded, loadErr = compile()
	})
	return loaded, loadErr
}

func compile() (*protoregistry.Files, error) {
	resolver := protocompile.WithStandardImports(&protocompile.SourceResolver{
		Accessor: func(path string) (io.ReadCloser, error) {
			return minimal.Files.Open(path)
		},
	})
	compiler := protocompile.Compiler{Resolver: resolver}
	compiled, err := compiler.Compile(context.Background(), sourceFiles...)
	if err != nil {
		return nil, err
	}

	registry := new(protoregistry.Files)
	registered := make(map[string]struct{})
	var register func(protoreflect.FileDescriptor) error
	register = func(file protoreflect.FileDescriptor) error {
		if _, ok := registered[file.Path()]; ok {
			return nil
		}
		imports := file.Imports()
		for index := 0; index < imports.Len(); index++ {
			dependency := imports.Get(index).FileDescriptor
			if dependency != nil {
				if err := register(dependency); err != nil {
					return err
				}
			}
		}
		if err := registry.RegisterFile(file); err != nil {
			return err
		}
		registered[file.Path()] = struct{}{}
		return nil
	}
	for _, file := range compiled {
		if err := register(file); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
