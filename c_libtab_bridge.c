#include <u.h>
#include <libc.h>
#include <stdint.h>
#include <sys/random.h>

#include "clibtab/tab_internal.h"
#include "monocypher.h"

enum {
	HashedDigest	= 32,
	HashedAlgoBlake	= 0x01,
	HashedAlgoArgon	= 0x02,

	Argon2dDefMlog2	= 16,
	Argon2dDefT	= 3,
	Argon2dDefP	= 1,
	Argon2dDefSalt	= 16,
	Argon2dMaxSalt	= 64,
	SignedSigLen	= 64,
};

static int
do_argon2id(uint8_t digest[HashedDigest],
	uint32_t m_log2, uint32_t t_passes, uint32_t p_lanes,
	const uint8_t *salt, uint32_t salt_len,
	const uint8_t *pass, uint32_t pass_len)
{
	crypto_argon2_config cfg;
	crypto_argon2_inputs in;
	uint64_t nb_blocks;
	void *work;

	cfg.algorithm = CRYPTO_ARGON2_ID;
	nb_blocks = (uint64_t)1 << m_log2;
	if(nb_blocks < 8ull * p_lanes){
		tab_seterror("argon2id: m too small for p lanes");
		return -1;
	}
	if(nb_blocks > 0xfffffffful){
		tab_seterror("argon2id: m too large");
		return -1;
	}
	cfg.nb_blocks = (uint32_t)nb_blocks;
	cfg.nb_passes = t_passes;
	cfg.nb_lanes = p_lanes;

	in.pass = pass;
	in.pass_size = pass_len;
	in.salt = salt;
	in.salt_size = salt_len;

	work = malloc((size_t)cfg.nb_blocks * 1024);
	if(work == nil){
		tab_seterror("argon2id: out of memory for work area (%u KiB)",
			cfg.nb_blocks);
		return -1;
	}
	crypto_argon2(digest, HashedDigest, work, cfg, in,
		crypto_argon2_no_extras);
	memset(work, 0, (size_t)cfg.nb_blocks * 1024);
	free(work);
	return 0;
}

static int
ct_eq(const uint8_t *a, const uint8_t *b, int n)
{
	int i, acc = 0;
	for(i = 0; i < n; i++)
		acc |= a[i] ^ b[i];
	return acc == 0;
}

char *
go_libtab_hash_blake2b(const unsigned char *preimage, int n)
{
	uint8_t digest[HashedDigest];
	uint8_t wire[1 + HashedDigest];
	char *cell;

	tab_clearerror();
	if(preimage == nil && n != 0){
		tab_seterror("go_libtab_hash_blake2b: nil preimage");
		return nil;
	}
	if(n < 0){
		tab_seterror("go_libtab_hash_blake2b: negative preimage length");
		return nil;
	}

	crypto_blake2b(digest, HashedDigest, preimage, (size_t)n);
	wire[0] = HashedAlgoBlake;
	memcpy(wire + 1, digest, HashedDigest);
	memset(digest, 0, sizeof digest);

	cell = tab_cell_encode("HASHED", wire, sizeof wire);
	memset(wire, 0, sizeof wire);
	return cell;
}

char *
go_libtab_hash_argon2id(const unsigned char *preimage, int n)
{
	uint8_t salt[Argon2dDefSalt];
	uint8_t digest[HashedDigest];
	uint8_t *wire;
	char *cell;
	int wlen;

	tab_clearerror();
	if(preimage == nil && n != 0){
		tab_seterror("go_libtab_hash_argon2id: nil preimage");
		return nil;
	}
	if(n < 0){
		tab_seterror("go_libtab_hash_argon2id: negative preimage length");
		return nil;
	}
	if(getrandom(salt, sizeof salt, 0) != (long)sizeof salt){
		tab_seterror("go_libtab_hash_argon2id: getrandom(salt) failed");
		return nil;
	}
	if(do_argon2id(digest, Argon2dDefMlog2, Argon2dDefT, Argon2dDefP,
		salt, sizeof salt, preimage, (uint32_t)n) < 0){
		memset(salt, 0, sizeof salt);
		return nil;
	}

	wlen = 1 + 4 + Argon2dDefSalt + HashedDigest;
	wire = malloc(wlen);
	if(wire == nil){
		tab_seterror("go_libtab_hash_argon2id: out of memory");
		memset(salt, 0, sizeof salt);
		memset(digest, 0, sizeof digest);
		return nil;
	}
	wire[0] = HashedAlgoArgon;
	wire[1] = Argon2dDefMlog2;
	wire[2] = Argon2dDefT;
	wire[3] = Argon2dDefP;
	wire[4] = Argon2dDefSalt;
	memcpy(wire + 5, salt, sizeof salt);
	memcpy(wire + 5 + sizeof salt, digest, HashedDigest);
	memset(salt, 0, sizeof salt);
	memset(digest, 0, sizeof digest);

	cell = tab_cell_encode("HASHED", wire, wlen);
	memset(wire, 0, wlen);
	free(wire);
	return cell;
}

int
go_libtab_verify_hash_cell(const char *cell, const unsigned char *preimage, int n)
{
	uint8_t *wire;
	uint8_t computed[HashedDigest];
	uint32_t salt_len;
	uint8_t algo, m_log2, t_passes, p_lanes;
	int wlen, ok;

	tab_clearerror();
	if(cell == nil || (preimage == nil && n != 0)){
		tab_seterror("go_libtab_verify_hash_cell: nil argument");
		return -1;
	}
	if(n < 0){
		tab_seterror("go_libtab_verify_hash_cell: negative preimage length");
		return -1;
	}

	wire = tab_cell_decode(cell, "HASHED", &wlen);
	if(wire == nil)
		return -1;
	if(wlen < 1){
		tab_seterror("go_libtab_verify_hash_cell: cell too short");
		free(wire);
		return -1;
	}

	algo = wire[0];
	switch(algo){
	case HashedAlgoBlake:
		if(wlen != 1 + HashedDigest){
			tab_seterror("go_libtab_verify_hash_cell: BLAKE2b cell length %d, want %d",
				wlen, 1 + HashedDigest);
			free(wire);
			return -1;
		}
		crypto_blake2b(computed, HashedDigest, preimage, (size_t)n);
		ok = ct_eq(wire + 1, computed, HashedDigest);
		memset(computed, 0, sizeof computed);
		free(wire);
		return ok ? 1 : 0;

	case HashedAlgoArgon:
		if(wlen < 1 + 4 + HashedDigest){
			tab_seterror("go_libtab_verify_hash_cell: argon2id cell too short");
			free(wire);
			return -1;
		}
		m_log2 = wire[1];
		t_passes = wire[2];
		p_lanes = wire[3];
		salt_len = wire[4];
		if(salt_len < 1 || salt_len > Argon2dMaxSalt){
			tab_seterror("go_libtab_verify_hash_cell: argon2id salt_len=%u out of range",
				salt_len);
			free(wire);
			return -1;
		}
		if(wlen != 1 + 4 + (int)salt_len + HashedDigest){
			tab_seterror("go_libtab_verify_hash_cell: argon2id cell length mismatches header");
			free(wire);
			return -1;
		}
		if(m_log2 < 3 || m_log2 > 24){
			tab_seterror("go_libtab_verify_hash_cell: argon2id m_log2=%u out of range",
				m_log2);
			free(wire);
			return -1;
		}
		if(t_passes < 1 || p_lanes < 1){
			tab_seterror("go_libtab_verify_hash_cell: argon2id t/p must be >= 1");
			free(wire);
			return -1;
		}
		if(do_argon2id(computed, m_log2, t_passes, p_lanes,
			wire + 5, salt_len, preimage, (uint32_t)n) < 0){
			free(wire);
			return -1;
		}
		ok = ct_eq(wire + 5 + salt_len, computed, HashedDigest);
		memset(computed, 0, sizeof computed);
		free(wire);
		return ok ? 1 : 0;

	default:
		tab_seterror("go_libtab_verify_hash_cell: unknown algo_id 0x%02x", algo);
		free(wire);
		return -1;
	}
}

char *
go_libtab_sign_body(const unsigned char *body, int n, const unsigned char *signer_sk)
{
	uint8_t sig[SignedSigLen];
	char *body_b64, *sig_b64, *out;
	int body_b64_len, sig_b64_len, total;
	static const char prefix[] = "signed:";
	const int prefix_len = sizeof prefix - 1;

	tab_clearerror();
	if(signer_sk == nil || (body == nil && n != 0)){
		tab_seterror("go_libtab_sign_body: nil argument");
		return nil;
	}
	if(n < 0){
		tab_seterror("go_libtab_sign_body: negative body length");
		return nil;
	}

	crypto_eddsa_sign(sig, signer_sk, body, (size_t)n);
	body_b64 = tab_b64_encode(body, n);
	if(body_b64 == nil){
		memset(sig, 0, sizeof sig);
		return nil;
	}
	sig_b64 = tab_b64_encode(sig, SignedSigLen);
	memset(sig, 0, sizeof sig);
	if(sig_b64 == nil){
		free(body_b64);
		return nil;
	}

	body_b64_len = strlen(body_b64);
	sig_b64_len = strlen(sig_b64);
	total = prefix_len + body_b64_len + 1 + sig_b64_len;
	out = malloc(total + 1);
	if(out == nil){
		tab_seterror("go_libtab_sign_body: out of memory");
		free(body_b64);
		free(sig_b64);
		return nil;
	}
	memcpy(out, prefix, prefix_len);
	memcpy(out + prefix_len, body_b64, body_b64_len);
	out[prefix_len + body_b64_len] = ':';
	memcpy(out + prefix_len + body_b64_len + 1, sig_b64, sig_b64_len);
	out[total] = 0;
	free(body_b64);
	free(sig_b64);
	return out;
}

unsigned char *
go_libtab_verify_signature_cell(const char *cell, const unsigned char *signer_pk, int *outlen)
{
	const char *p, *colon;
	char *body_b64;
	unsigned char *body, *sig_bytes;
	uint8_t sig[SignedSigLen];
	int body_b64_len, sig_len, body_len;
	static const char prefix[] = "signed:";
	const int prefix_len = sizeof prefix - 1;

	tab_clearerror();
	if(cell == nil || signer_pk == nil || outlen == nil){
		tab_seterror("go_libtab_verify_signature_cell: nil argument");
		return nil;
	}
	if(strncmp(cell, prefix, prefix_len) != 0){
		tab_seterror("go_libtab_verify_signature_cell: cell missing signed: prefix");
		return nil;
	}

	p = cell + prefix_len;
	colon = strchr(p, ':');
	if(colon == nil){
		tab_seterror("go_libtab_verify_signature_cell: cell missing inner ':'");
		return nil;
	}
	body_b64_len = (int)(colon - p);
	body_b64 = malloc(body_b64_len + 1);
	if(body_b64 == nil){
		tab_seterror("go_libtab_verify_signature_cell: out of memory");
		return nil;
	}
	memcpy(body_b64, p, body_b64_len);
	body_b64[body_b64_len] = 0;
	body = tab_b64_decode(body_b64, &body_len);
	free(body_b64);
	if(body == nil)
		return nil;

	sig_bytes = tab_b64_decode(colon + 1, &sig_len);
	if(sig_bytes == nil){
		free(body);
		return nil;
	}
	if(sig_len != SignedSigLen){
		tab_seterror("go_libtab_verify_signature_cell: signature is %d bytes, want %d",
			sig_len, SignedSigLen);
		free(body);
		free(sig_bytes);
		return nil;
	}
	memcpy(sig, sig_bytes, SignedSigLen);
	free(sig_bytes);

	if(crypto_eddsa_check(sig, signer_pk, body, (size_t)body_len) != 0){
		tab_seterror("go_libtab_verify_signature_cell: signature check failed");
		memset(body, 0, body_len);
		free(body);
		return nil;
	}
	*outlen = body_len;
	return body;
}

void
go_libtab_eddsa_key_pair(unsigned char *secret_key, unsigned char *public_key,
	unsigned char *seed)
{
	crypto_eddsa_key_pair(secret_key, public_key, seed);
}
