package pbkdf2

// Password-Based Key Derivation Function 2
// Based on:
//   http://tools.ietf.org/html/rfc2898
//   http://en.wikipedia.org/wiki/PBKDF2
//   https://www.ietf.org/rfc/rfc6070.txt

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"
	"math"
)

// NIST SP 800-132 complies with FIPS 140-2/ISO 27001
// Recommendation for Password-Based Key Derivation for storage
// http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

type pbkdf2 struct {
	size                 int
	blockSize            int
	bitBlockCount        int
	bigEdian             [4]byte
	U                    []byte
	iterations           int
	pseudoRandomFunction hash.Hash
}

// New is a factory method, which returns a new PBKDF2 hash using the given
// hash.Hash function type, password, salt, number of interations, and the
// desired byte length of the output.
func New(hashingFunction func() hash.Hash, password []byte,
	iterations, length int) hash.Hash {

	PBKDF2 := new(pbkdf2)
	PBKDF2.pseudoRandomFunction = hmac.New(hashingFunction, password)
	PBKDF2.iterations = iterations
	PBKDF2.size = length
	PBKDF2.blockSize = PBKDF2.pseudoRandomFunction.BlockSize()
	PBKDF2.bitBlockCount = PBKDF2.getHashLengthBitBlockCount()
	PBKDF2.U = make([]byte, PBKDF2.pseudoRandomFunction.Size())
	return PBKDF2
}

// getHashLengthBitBlockCount is used to figure out how many T interations are
// needed to satisfy the desired hash length.
// Example:
//   bitBlockCount = derivedKeyLength / hashLength
//   derivedKey = T_1 || T_2 || ... || T_bitBlockCount
func (p *pbkdf2) getHashLengthBitBlockCount() int {
	return int(math.Ceil(float64(p.size) / float64(p.pseudoRandomFunction.Size())))
}

// generateMultipleBitBlocks creates each bit block to compensate for pseudo
// random functions lack of length.
// Each hashLength-bit block (T_i) of derived key (DK), is computed as follows:
//   DK  = T_1 || T_2 || ... || T_dkLength/hashingLength
//   T_i = F(Password, Salt, c, i)
func (p *pbkdf2) generateBitBlocks(salt []byte) []byte {
	derivedKey := make([]byte, 0, p.bitBlockCount*p.pseudoRandomFunction.Size())

	for currentBlock := 1; currentBlock <= p.bitBlockCount; currentBlock++ {
		p.appendUintToSalt(currentBlock, salt)

		derivedKey = p.pseudoRandomFunction.Sum(derivedKey)
		// Slice reference to derivedKey
		T := derivedKey[len(derivedKey)-p.pseudoRandomFunction.Size():]
		// Copy T slice to U
		copy(p.U, T)

		p.doIterations(T)
	}
	return derivedKey[:p.size]
}

// appendUintToSalt this method will append a unassigned integer to the salt
// for the first U iteration.
// Example:
//   U_i
//   U_1 = pseudoRandomFunction(password, salt || uint(i))
//   i   = 1
func (p *pbkdf2) appendUintToSalt(currentBlock int, salt []byte) {
	p.Reset()
	p.Write(salt)

	// Big edian 32 bit uint(i)
	p.bigEdian[0] = byte(currentBlock >> 24)
	p.bigEdian[1] = byte(currentBlock >> 16)
	p.bigEdian[2] = byte(currentBlock >> 8)
	p.bigEdian[3] = byte(currentBlock)

	// Append to salt
	p.Write(p.bigEdian[:4])
}

// doIterations will do U XORs based on the number iterations specified.
// Example:
//   U_n = pseudoRandomFunction(password, U_(n-1))
func (p *pbkdf2) doIterations(T []byte) {
	for n := 2; n <= p.iterations; n++ {
		p.Reset()
		p.Write(p.U)
		// Nil out p.U before passing it into Sum().
		p.U = p.U[:0]
		p.U = p.pseudoRandomFunction.Sum(p.U)
		for x := range p.U {
			// Updates derivedKey since T is a reference slice to it.
			T[x] ^= p.U[x]
		}
	}
}

func (p *pbkdf2) Write(writeSalt []byte) (numBytesWritten int, err error) {
	return p.pseudoRandomFunction.Write(writeSalt)
}

func (p *pbkdf2) Sum(salt []byte) []byte {
	if salt != nil {
		p.Write(salt)
	}
	return p.generateBitBlocks(salt)
}

func (p *pbkdf2) Reset() {
	p.pseudoRandomFunction.Reset()
}

func (p *pbkdf2) Size() int { return p.size }

func (p *pbkdf2) BlockSize() int { return p.blockSize }

// Equal compares two PBKDF2s for quality wihtout leaking timeing information.
func Equal(PBKDF2_x, PBKDF2_y []byte) bool {
	return len(PBKDF2_x) == len(PBKDF2_y) &&
		subtle.ConstantTimeCompare(PBKDF2_x, PBKDF2_y) == 1
}
