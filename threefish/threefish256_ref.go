// In threefish256_ref.go

package threefish

// Shared state to avoid allocations
var (
	globalBlock [4]uint64
	globalTmp   uint64
)

func (t *threefish256) Encrypt(dst, src []byte) {
	bytesToBlock256(&globalBlock, src)
	Encrypt256(&globalBlock, &(t.keys), &(t.tweak))
	block256ToBytes(dst, &globalBlock)
}

func (t *threefish256) Decrypt(dst, src []byte) {
	bytesToBlock256(&globalBlock, src)
	Decrypt256(&globalBlock, &(t.keys), &(t.tweak))
	block256ToBytes(dst, &globalBlock)
}

func Decrypt256(block *[4]uint64, keys *[5]uint64, tweak *[3]uint64) {
	b0, b1, b2, b3 := block[0], block[1], block[2], block[3]

	for r := 18; r > 1; r-- {
		b0 -= keys[r%5]
		b1 -= keys[(r+1)%5] + tweak[r%3]
		b2 -= keys[(r+2)%5] + tweak[(r+1)%3]
		b3 -= keys[(r+3)%5] + uint64(r)

		globalTmp = b1 ^ b2
		b1 = (globalTmp >> 32) | (globalTmp << (64 - 32))
		b2 -= b1
		globalTmp = b3 ^ b0
		b3 = (globalTmp >> 32) | (globalTmp << (64 - 32))
		b0 -= b3

		// ... rest of decryption rounds using globalTmp for temporary operations ...
	}

	b0 -= keys[0]
	b1 -= keys[1] + tweak[0]
	b2 -= keys[2] + tweak[1]
	b3 -= keys[3]

	block[0], block[1], block[2], block[3] = b0, b1, b2, b3
}

func Encrypt256(block *[4]uint64, keys *[5]uint64, tweak *[3]uint64) {
	b0, b1, b2, b3 := block[0], block[1], block[2], block[3]

	for r := 0; r < 17; r++ {
		b0 += keys[r%5]
		b1 += keys[(r+1)%5] + tweak[r%3]
		b2 += keys[(r+2)%5] + tweak[(r+1)%3]
		b3 += keys[(r+3)%5] + uint64(r)

		b0 += b1
		b1 = ((b1 << 14) | (b1 >> (64 - 14))) ^ b0
		b2 += b3
		b3 = ((b3 << 16) | (b3 >> (64 - 16))) ^ b2

		// ... rest of encryption rounds ...
	}

	block[0], block[1], block[2], block[3] = b0, b1, b2, b3
}

func UBI256(block *[4]uint64, hVal *[5]uint64, tweak *[3]uint64) {
	b0, b1, b2, b3 := block[0], block[1], block[2], block[3]

	hVal[4] = C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^ hVal[3]
	tweak[2] = tweak[0] ^ tweak[1]

	Encrypt256(block, hVal, tweak)

	hVal[0] = block[0] ^ b0
	hVal[1] = block[1] ^ b1
	hVal[2] = block[2] ^ b2
	hVal[3] = block[3] ^ b3
}
func newCipher256(tweak *[TweakSize]byte, key []byte) *threefish256 {
	c := new(threefish256)

	c.tweak[0] = uint64(tweak[0]) | uint64(tweak[1])<<8 | uint64(tweak[2])<<16 | uint64(tweak[3])<<24 |
		uint64(tweak[4])<<32 | uint64(tweak[5])<<40 | uint64(tweak[6])<<48 | uint64(tweak[7])<<56

	c.tweak[1] = uint64(tweak[8]) | uint64(tweak[9])<<8 | uint64(tweak[10])<<16 | uint64(tweak[11])<<24 |
		uint64(tweak[12])<<32 | uint64(tweak[13])<<40 | uint64(tweak[14])<<48 | uint64(tweak[15])<<56

	c.tweak[2] = c.tweak[0] ^ c.tweak[1]

	for i := range c.keys[:4] {
		j := i * 8
		c.keys[i] = uint64(key[j]) | uint64(key[j+1])<<8 | uint64(key[j+2])<<16 | uint64(key[j+3])<<24 |
			uint64(key[j+4])<<32 | uint64(key[j+5])<<40 | uint64(key[j+6])<<48 | uint64(key[j+7])<<56
	}
	c.keys[4] = C240 ^ c.keys[0] ^ c.keys[1] ^ c.keys[2] ^ c.keys[3]

	return c
}
