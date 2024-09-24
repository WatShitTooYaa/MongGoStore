package primitive

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// ObjectID is a custom 12-byte identifier, similar to MongoDB ObjectID.
type ObjectID [12]byte

var (
	machineID       = generateMachineID()
	processID       = uint16(os.Getpid())
	objectIDCounter uint32
)

func init() {
	// Seed counter with a random number
	var b [4]byte
	_, _ = rand.Read(b[:])
	objectIDCounter = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// NewObjectID generates a new ObjectID.
func NewObjectID() ObjectID {
	var id ObjectID

	// 4-byte timestamp (current time in seconds since epoch)
	timestamp := uint32(time.Now().Unix())
	id[0] = byte(timestamp >> 24)
	id[1] = byte(timestamp >> 16)
	id[2] = byte(timestamp >> 8)
	id[3] = byte(timestamp)

	// 3-byte machine identifier
	id[4] = machineID[0]
	id[5] = machineID[1]
	id[6] = machineID[2]

	// 2-byte process identifier
	id[7] = byte(processID >> 8)
	id[8] = byte(processID)

	// 3-byte counter, incrementing
	counter := atomic.AddUint32(&objectIDCounter, 1)
	id[9] = byte(counter >> 16)
	id[10] = byte(counter >> 8)
	id[11] = byte(counter)

	return id
}

// Hex returns the hexadecimal string representation of the ObjectID.
func (id ObjectID) Hex() string {
	return hex.EncodeToString(id[:])
}

// generateMachineID creates a unique machine identifier.
func generateMachineID() [3]byte {
	var id [3]byte
	hostname, err := os.Hostname()
	if err != nil {
		_, _ = rand.Read(id[:])
		return id
	}
	copy(id[:], hostname)
	return id
}

// ObjectIDFromHex creates an ObjectID from a hex string.
func ObjectIDFromHex(hexStr string) (ObjectID, error) {
	var id ObjectID

	// Ensure the string is exactly 24 characters (12 bytes)
	if len(hexStr) != 24 {
		return id, errors.New("ObjectID must be exactly 24 hexadecimal characters")
	}

	// Convert the hex string to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return id, fmt.Errorf("invalid hex string: %v", err)
	}

	// Copy the bytes into the ObjectID
	copy(id[:], bytes)

	return id, nil
}
