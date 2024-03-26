package attack

import (
	"fmt"
	"hash/crc32"
)

func xorBytes(a []byte, b []byte) []byte {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		byteA := byte(0)
		byteB := byte(0)
		if i < len(a) {
			byteA = a[i]
		}
		if i < len(b) {
			byteB = b[i]
		}
		result[i] = byteA ^ byteB
	}
	return result
}

func Attack() {
	// Define two arbitrary byte slices a and b
	a := []byte("hello")
	b := []byte("world")

	// Compute CRC32 checksums for a, b, and a XOR b
	crcA := crc32.ChecksumIEEE(a)
	crcB := crc32.ChecksumIEEE(b)
	aXORb := xorBytes(a, b)
	crcAXORb := crc32.ChecksumIEEE(aXORb)

	// Compute CRC(a) XOR CRC(b) and compare with CRC(a XOR b)
	crcAXORcrcB := crcA ^ crcB

	fmt.Printf("CRC(a): %08x\n", crcA)
	fmt.Printf("CRC(b): %08x\n", crcB)
	fmt.Printf("CRC(a) XOR CRC(b): %08x\n", crcAXORcrcB)
	fmt.Printf("CRC(a XOR b): %08x\n", crcAXORb)

	// Check if CRC(a) XOR CRC(b) equals CRC(a XOR b)
	if crcAXORcrcB == crcAXORb {
		fmt.Println("CRC(a) XOR CRC(b) equals CRC(a XOR b)")
	} else {
		fmt.Println("CRC(a) XOR CRC(b) does not equal CRC(a XOR b)")
	}
}

// write a cca attack
func chosenCipherText() {

}
