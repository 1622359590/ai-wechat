// Package minimal exposes the recovered protocol sources as embedded assets.
package minimal

import "embed"

// Files contains only the reviewed minimal Protobuf sources.
//
//go:embed *.proto
var Files embed.FS
