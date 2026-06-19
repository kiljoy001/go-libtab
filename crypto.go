package libtab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

const (
	HashedDigest    = 32
	HashedAlgoBlake = 0x01
	HashedAlgoArgon = 0x02

	Argon2dDefMlog2 = 16 // 64 MiB
	Argon2dDefT     = 3
	Argon2dDefP     = 1
	Argon2dDefSalt  = 16
)

func HashBlake2b(preimage []byte) (string, error) {
	digest := blake2b.Sum256(preimage)
	wire := make([]byte, 1+HashedDigest)
	wire[0] = HashedAlgoBlake
	copy(wire[1:], digest[:])
	return "hashed:" + B64Encode(wire), nil
}

func HashArgon2id(preimage []byte) (string, error) {
	salt := make([]byte, Argon2dDefSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate secure salt: %v", err)
	}

	m := uint32(1 << Argon2dDefMlog2)
	digest := argon2.IDKey(preimage, salt, Argon2dDefT, m, Argon2dDefP, HashedDigest)

	wlen := 5 + Argon2dDefSalt + HashedDigest
	wire := make([]byte, wlen)
	wire[0] = HashedAlgoArgon
	wire[1] = Argon2dDefMlog2
	wire[2] = Argon2dDefT
	wire[3] = Argon2dDefP
	wire[4] = Argon2dDefSalt
	copy(wire[5:], salt)
	copy(wire[5+Argon2dDefSalt:], digest)

	return "hashed:" + B64Encode(wire), nil
}

func VerifyHash(cellVal string, preimage []byte) (bool, error) {
	if !strings.HasPrefix(cellVal, "hashed:") {
		return false, fmt.Errorf("missing hashed: prefix")
	}
	b64Part := cellVal[len("hashed:"):]
	wire, err := B64Decode(b64Part)
	if err != nil {
		return false, fmt.Errorf("failed to decode base64 cell: %v", err)
	}

	if len(wire) == 0 {
		return false, fmt.Errorf("empty hashed cell payload")
	}

	algo := wire[0]
	switch algo {
	case HashedAlgoBlake:
		if len(wire) != 1+HashedDigest {
			return false, fmt.Errorf("invalid blake2b wire length %d", len(wire))
		}
		digest := blake2b.Sum256(preimage)
		return subtle.ConstantTimeCompare(wire[1:], digest[:]) == 1, nil

	case HashedAlgoArgon:
		if len(wire) < 5 {
			return false, fmt.Errorf("invalid argon2id wire header")
		}
		mLog2 := wire[1]
		t := wire[2]
		p := wire[3]
		saltLen := int(wire[4])

		if len(wire) != 5+saltLen+HashedDigest {
			return false, fmt.Errorf("invalid argon2id wire length %d, expected %d", len(wire), 5+saltLen+HashedDigest)
		}

		salt := wire[5 : 5+saltLen]
		expectedDigest := wire[5+saltLen : 5+saltLen+HashedDigest]

		m := uint32(1 << mLog2)
		computedDigest := argon2.IDKey(preimage, salt, uint32(t), m, p, HashedDigest)

		return subtle.ConstantTimeCompare(computedDigest, expectedDigest) == 1, nil

	default:
		return false, fmt.Errorf("unknown hash algorithm ID 0x%02x", algo)
	}
}

func SignBody(body []byte, privKey ed25519.PrivateKey) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size: %d", len(privKey))
	}
	sig := ed25519.Sign(privKey, body)
	return fmt.Sprintf("signed:%s:%s", B64Encode(body), B64Encode(sig)), nil
}

func VerifySignature(cellVal string, pubKey ed25519.PublicKey) ([]byte, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubKey))
	}
	if !strings.HasPrefix(cellVal, "signed:") {
		return nil, fmt.Errorf("missing signed: prefix")
	}

	parts := strings.Split(cellVal[len("signed:"):], ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid signed cell format, expected signed:<body_b64>:<sig_b64>")
	}

	body, err := B64Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed body: %v", err)
	}

	sig, err := B64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature size %d", len(sig))
	}

	if !ed25519.Verify(pubKey, body, sig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return body, nil
}
