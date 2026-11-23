// Package protocol reads a frame's length from its header.
package protocol

// Length is the length a frame's first byte says, never checked against
// what the frame holds: the hole the exploit shows.
func Length(frame []byte) int {
	if len(frame) == 0 {
		return 0
	}
	return int(frame[0])
}
