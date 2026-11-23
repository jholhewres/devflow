// Package app reads frames with the protocol module beside it.
package app

import "example.test/protocol"

// Size is a frame's size as the protocol reads it.
func Size(frame []byte) int { return protocol.Length(frame) }
