//go:build !protocol_fast

package protocol

func init() { panic("protocol built without its protocol_fast tag") }
