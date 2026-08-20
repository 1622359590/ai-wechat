package schema_test

import (
	"sync"
	"testing"

	"github.com/1622359590/ai-wechat/proto/schema"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestLoadReturnsSixCachedProto3Files(t *testing.T) {
	const workers = 8
	results := make(chan any, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup

	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			files, err := schema.Load()
			if err != nil {
				errors <- err
				return
			}
			results <- files
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatalf("load schema: %v", err)
	}

	var first any
	for files := range results {
		if first == nil {
			first = files
		} else if files != first {
			t.Fatal("Load returned a different cached registry")
		}
	}

	registry, err := schema.Load()
	if err != nil {
		t.Fatalf("load schema for inspection: %v", err)
	}
	descriptor, err := registry.FindDescriptorByName("Jubo.JuLiao.IM.Wx.Proto.TransportMessage")
	if err != nil {
		t.Fatalf("find TransportMessage: %v", err)
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("TransportMessage descriptor is %T", descriptor)
	}
	if got, want := message.ParentFile().Syntax(), protoreflect.Proto3; got != want {
		t.Fatalf("syntax = %s, want %s", got, want)
	}

	count := 0
	registry.RangeFiles(func(protoreflect.FileDescriptor) bool {
		count++
		return true
	})
	if got, want := count, 7; got != want {
		t.Fatalf("registered file count = %d, want %d (six recovered plus Any)", got, want)
	}
}
