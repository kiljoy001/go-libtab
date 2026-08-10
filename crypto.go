package libtab

/*
#cgo CFLAGS: -DPLAN9PORT -I${SRCDIR}/clibtab -I${SRCDIR} -I/usr/local/plan9/include

#include <u.h>
#include <libc.h>

char *go_libtab_hash_blake2b(const unsigned char *preimage, int n);
char *go_libtab_hash_argon2id(const unsigned char *preimage, int n);
int go_libtab_verify_hash_cell(const char *cell, const unsigned char *preimage, int n);
char *go_libtab_sign_body(const unsigned char *body, int n, const unsigned char *signer_sk);
unsigned char *go_libtab_verify_signature_cell(const char *cell, const unsigned char *signer_pk, int *outlen);
void go_libtab_eddsa_key_pair(unsigned char *secret_key, unsigned char *public_key, unsigned char *seed);
*/
import "C"

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

func HashBlake2b(preimage []byte) (string, error) {
	var in *C.uchar
	if len(preimage) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&preimage[0]))
	}

	cell := C.go_libtab_hash_blake2b(in, C.int(len(preimage)))
	if cell == nil {
		return "", lastError()
	}
	defer freePlan9(unsafe.Pointer(cell))
	return C.GoString(cell), nil
}

func HashArgon2id(preimage []byte) (string, error) {
	var in *C.uchar
	if len(preimage) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&preimage[0]))
	}

	cell := C.go_libtab_hash_argon2id(in, C.int(len(preimage)))
	if cell == nil {
		return "", lastError()
	}
	defer freePlan9(unsafe.Pointer(cell))
	return C.GoString(cell), nil
}

func VerifyHash(cellVal string, preimage []byte) (bool, error) {
	ccell := cString(cellVal)
	defer freeCString(ccell)

	var in *C.uchar
	if len(preimage) > 0 {
		in = (*C.uchar)(unsafe.Pointer(&preimage[0]))
	}

	rc := C.go_libtab_verify_hash_cell(ccell, in, C.int(len(preimage)))
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, lastError()
	}
}

func SignBody(body []byte, privKey []byte) (string, error) {
	if len(privKey) != 64 {
		return "", fmt.Errorf("invalid private key size: %d", len(privKey))
	}

	var bodyPtr *C.uchar
	if len(body) > 0 {
		bodyPtr = (*C.uchar)(unsafe.Pointer(&body[0]))
	}
	keyPtr := (*C.uchar)(unsafe.Pointer(&privKey[0]))

	cell := C.go_libtab_sign_body(bodyPtr, C.int(len(body)), keyPtr)
	if cell == nil {
		return "", lastError()
	}
	defer freePlan9(unsafe.Pointer(cell))
	return C.GoString(cell), nil
}

func VerifySignature(cellVal string, pubKey []byte) ([]byte, error) {
	if len(pubKey) != 32 {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubKey))
	}

	ccell := cString(cellVal)
	defer freeCString(ccell)

	var outLen C.int
	keyPtr := (*C.uchar)(unsafe.Pointer(&pubKey[0]))
	body := C.go_libtab_verify_signature_cell(ccell, keyPtr, &outLen)
	if body == nil {
		return nil, lastError()
	}
	defer freePlan9(unsafe.Pointer(body))

	return C.GoBytes(unsafe.Pointer(body), outLen), nil
}

func SigningKeyPairFromSeed(seed []byte) (pubKey []byte, privKey []byte, err error) {
	if len(seed) != 32 {
		return nil, nil, fmt.Errorf("invalid seed size: %d", len(seed))
	}

	var cpub [32]C.uchar
	var cpriv [64]C.uchar
	seedPtr := (*C.uchar)(unsafe.Pointer(&seed[0]))

	C.go_libtab_eddsa_key_pair(&cpriv[0], &cpub[0], seedPtr)
	return C.GoBytes(unsafe.Pointer(&cpub[0]), 32), C.GoBytes(unsafe.Pointer(&cpriv[0]), 64), nil
}

func GenerateSigningKey() (pubKey []byte, privKey []byte, err error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return SigningKeyPairFromSeed(seed)
}

func EncryptBody(body []byte, key []byte) (string, error) {
	return "", fmt.Errorf("ENCRYPTED cells are not supported by C libtab")
}

func DecryptBody(cellVal string, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("ENCRYPTED cells are not supported by C libtab")
}
