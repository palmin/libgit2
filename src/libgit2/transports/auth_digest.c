/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "auth.h"

#include "common.h"
#include "str.h"
#include "rand.h"
#include "git2/sys/credential.h"

#include <stdio.h>

/*
 * HTTP Digest authentication (RFC 7616, with RFC 2617/2069 fallback).
 * qop=auth only; algorithms MD5 and SHA-256 (and their -sess variants).
 * Registered after Basic in httpclient's scheme table, so a server that
 * offers Basic (over TLS) keeps using Basic and Digest engages only where
 * Basic is absent (a plain-http server that offers Digest alone).
 *
 * Apple-only crypto: this fork always builds against CommonCrypto.
 */
#include <CommonCrypto/CommonDigest.h>

typedef enum {
	DIGEST_ALG_MD5 = 0,
	DIGEST_ALG_SHA256
} digest_algorithm;

typedef struct {
	git_http_auth_context parent;

	/* parsed from the WWW-Authenticate challenge */
	char *realm;
	char *nonce;
	char *opaque;      /* echoed verbatim when present */
	char *algorithm;   /* raw token to echo back, e.g. "SHA-256" */
	digest_algorithm alg;
	bool sess;         /* the -sess variant */
	bool has_qop;      /* server offered qop=auth */
	bool usable;       /* challenge parsed and algorithm supported */

	/* current request */
	char *method;
	char *target;

	/* nonce count, reset to 0 whenever the nonce changes */
	unsigned int nc;
} http_auth_digest_context;

#define DIGEST_MAX_HEX (CC_SHA256_DIGEST_LENGTH * 2 + 1)

GIT_INLINE(bool) is_token_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '-';
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = hex[bytes[i] >> 4];
		out[i * 2 + 1] = hex[bytes[i] & 0x0f];
	}
	out[len * 2] = '\0';
}

/* hex(H(data)) into `out` (at least DIGEST_MAX_HEX bytes) */
static void digest_hash(
	digest_algorithm alg,
	const char *data,
	size_t len,
	char *out)
{
	if (alg == DIGEST_ALG_SHA256) {
		unsigned char d[CC_SHA256_DIGEST_LENGTH];
		CC_SHA256(data, (CC_LONG)len, d);
		bytes_to_hex(d, sizeof(d), out);
	} else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		unsigned char d[CC_MD5_DIGEST_LENGTH];
		CC_MD5(data, (CC_LONG)len, d);
#pragma clang diagnostic pop
		bytes_to_hex(d, sizeof(d), out);
	}
}

/*
 * Extracts an auth-param value by name from a Digest challenge. Handles
 * quoted strings (with backslash escapes) and bare tokens. Returns a newly
 * allocated string, or NULL when the param is absent.
 */
static char *digest_param(const char *challenge, const char *key)
{
	size_t keylen = strlen(key);
	const char *p = challenge;

	while ((p = strstr(p, key)) != NULL) {
		const char *after = p + keylen;

		/* the match must be a whole token, not a suffix (nonce vs cnonce) */
		if ((p == challenge || !is_token_char(p[-1]))) {
			while (*after == ' ' || *after == '\t')
				after++;

			if (*after == '=') {
				git_str value = GIT_STR_INIT;
				char *result;

				after++;
				while (*after == ' ' || *after == '\t')
					after++;

				if (*after == '"') {
					after++;
					while (*after && *after != '"') {
						if (*after == '\\' && after[1])
							after++;
						git_str_putc(&value, *after++);
					}
				} else {
					while (*after && *after != ',' &&
					       *after != ' ' && *after != '\t')
						git_str_putc(&value, *after++);
				}

				if (git_str_oom(&value)) {
					git_str_dispose(&value);
					return NULL;
				}

				result = git__strdup(git_str_cstr(&value));
				git_str_dispose(&value);
				return result;
			}
		}

		p += keylen;
	}

	return NULL;
}

static int digest_set_challenge(
	git_http_auth_context *c,
	const char *challenge)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;
	const char *params;
	char *qop, *previous_nonce;

	GIT_ASSERT_ARG(ctx);
	GIT_ASSERT_ARG(challenge);

	if (strncasecmp(challenge, "Digest", 6) != 0) {
		git_error_set(GIT_ERROR_HTTP, "challenge is not Digest");
		return -1;
	}
	params = challenge + 6;

	ctx->usable = false;
	previous_nonce = ctx->nonce;
	ctx->nonce = NULL;

	git__free(ctx->realm);
	git__free(ctx->opaque);
	git__free(ctx->algorithm);
	ctx->realm = digest_param(params, "realm");
	ctx->nonce = digest_param(params, "nonce");
	ctx->opaque = digest_param(params, "opaque");
	ctx->algorithm = digest_param(params, "algorithm");

	/* a new nonce restarts the nonce count */
	if (!previous_nonce || !ctx->nonce ||
	    strcmp(previous_nonce, ctx->nonce) != 0)
		ctx->nc = 0;
	git__free(previous_nonce);

	if (!ctx->realm || !ctx->nonce) {
		git_error_set(GIT_ERROR_HTTP, "malformed Digest challenge");
		return -1;
	}

	/* algorithm defaults to MD5 when the server omits it (RFC 2617) */
	if (!ctx->algorithm) {
		ctx->alg = DIGEST_ALG_MD5;
		ctx->sess = false;
	} else if (strncasecmp(ctx->algorithm, "SHA-256", 7) == 0) {
		ctx->alg = DIGEST_ALG_SHA256;
		ctx->sess = strcasecmp(ctx->algorithm, "SHA-256-sess") == 0;
	} else if (strncasecmp(ctx->algorithm, "MD5", 3) == 0) {
		ctx->alg = DIGEST_ALG_MD5;
		ctx->sess = strcasecmp(ctx->algorithm, "MD5-sess") == 0;
	} else {
		/* e.g. SHA-512-256: leave unusable, next_token fails cleanly */
		return 0;
	}

	/* qop may be a list ("auth,auth-int"); we can only satisfy auth */
	qop = digest_param(params, "qop");
	ctx->has_qop = false;
	if (qop) {
		const char *found = strstr(qop, "auth");
		while (found) {
			char before = (found == qop) ? ',' : found[-1];
			char after = found[4];
			if ((before == ',' || before == ' ' || before == '"') &&
			    (after == '\0' || after == ',' || after == ' ' || after == '"')) {
				ctx->has_qop = true;
				break;
			}
			found = strstr(found + 1, "auth");
		}
		git__free(qop);
	}

	ctx->usable = true;
	return 0;
}

static int digest_set_request(
	git_http_auth_context *c,
	const char *method,
	const char *target)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;

	GIT_ASSERT_ARG(ctx);
	GIT_ASSERT_ARG(method);
	GIT_ASSERT_ARG(target);

	git__free(ctx->method);
	git__free(ctx->target);

	ctx->method = git__strdup(method);
	ctx->target = git__strdup(target);
	GIT_ERROR_CHECK_ALLOC(ctx->method);
	GIT_ERROR_CHECK_ALLOC(ctx->target);

	return 0;
}

static int digest_next_token(
	git_str *buf,
	git_http_auth_context *c,
	git_credential *cred)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;
	git_credential_userpass_plaintext *userpass;
	git_str scratch = GIT_STR_INIT;
	char ha1[DIGEST_MAX_HEX], ha2[DIGEST_MAX_HEX], response[DIGEST_MAX_HEX];
	char cnonce[17], nc_str[9];
	uint64_t r1, r2;
	int error = GIT_EAUTH;

	GIT_ASSERT_ARG(buf);
	GIT_ASSERT_ARG(ctx);

	if (!ctx->usable) {
		git_error_set(GIT_ERROR_HTTP, "unsupported Digest challenge");
		return GIT_EAUTH;
	}

	if (cred->credtype != GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
		git_error_set(GIT_ERROR_INVALID, "invalid credential type for Digest auth");
		return GIT_EAUTH;
	}

	if (!ctx->method || !ctx->target) {
		git_error_set(GIT_ERROR_HTTP, "Digest auth has no request context");
		return GIT_EAUTH;
	}

	userpass = (git_credential_userpass_plaintext *)cred;

	/* a fresh client nonce and the next nonce count for this request */
	r1 = git_rand_next();
	r2 = git_rand_next();
	snprintf(cnonce, sizeof(cnonce), "%08x%08x",
		(unsigned int)(r1 & 0xffffffff), (unsigned int)(r2 & 0xffffffff));
	ctx->nc++;
	snprintf(nc_str, sizeof(nc_str), "%08x", ctx->nc);

	/* HA1 = H(username:realm:password), with the -sess extension */
	git_str_printf(&scratch, "%s:%s:%s",
		userpass->username, ctx->realm, userpass->password);
	if (git_str_oom(&scratch))
		goto done;
	digest_hash(ctx->alg, scratch.ptr, scratch.size, ha1);

	if (ctx->sess) {
		git_str_clear(&scratch);
		git_str_printf(&scratch, "%s:%s:%s", ha1, ctx->nonce, cnonce);
		if (git_str_oom(&scratch))
			goto done;
		digest_hash(ctx->alg, scratch.ptr, scratch.size, ha1);
	}

	/* HA2 = H(method:uri) for qop=auth */
	git_str_clear(&scratch);
	git_str_printf(&scratch, "%s:%s", ctx->method, ctx->target);
	if (git_str_oom(&scratch))
		goto done;
	digest_hash(ctx->alg, scratch.ptr, scratch.size, ha2);

	/* response */
	git_str_clear(&scratch);
	if (ctx->has_qop)
		git_str_printf(&scratch, "%s:%s:%s:%s:auth:%s",
			ha1, ctx->nonce, nc_str, cnonce, ha2);
	else
		git_str_printf(&scratch, "%s:%s:%s", ha1, ctx->nonce, ha2);
	if (git_str_oom(&scratch))
		goto done;
	digest_hash(ctx->alg, scratch.ptr, scratch.size, response);

	git_str_printf(buf,
		"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
		userpass->username, ctx->realm, ctx->nonce, ctx->target, response);

	if (ctx->algorithm)
		git_str_printf(buf, ", algorithm=%s", ctx->algorithm);

	if (ctx->has_qop)
		git_str_printf(buf, ", qop=auth, nc=%s, cnonce=\"%s\"", nc_str, cnonce);

	if (ctx->opaque)
		git_str_printf(buf, ", opaque=\"%s\"", ctx->opaque);

	if (git_str_oom(buf))
		goto done;

	error = 0;

done:
	/* HA1 and the scratch buffer are derived from the password */
	git__memzero(ha1, sizeof(ha1));
	if (scratch.size)
		git__memzero(scratch.ptr, scratch.size);
	git_str_dispose(&scratch);
	return error;
}

static void digest_context_free(git_http_auth_context *c)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;

	git__free(ctx->realm);
	git__free(ctx->nonce);
	git__free(ctx->opaque);
	git__free(ctx->algorithm);
	git__free(ctx->method);
	git__free(ctx->target);
	git__free(ctx);
}

int git_http_auth_digest(
	git_http_auth_context **out,
	const git_net_url *url)
{
	http_auth_digest_context *ctx;

	GIT_UNUSED(url);

	ctx = git__calloc(1, sizeof(http_auth_digest_context));
	GIT_ERROR_CHECK_ALLOC(ctx);

	ctx->parent.type = GIT_HTTP_AUTH_DIGEST;
	ctx->parent.credtypes = GIT_CREDENTIAL_USERPASS_PLAINTEXT;
	/* request affinity: a token is produced for every request, like Basic */
	ctx->parent.connection_affinity = 0;
	ctx->parent.set_challenge = digest_set_challenge;
	ctx->parent.next_token = digest_next_token;
	ctx->parent.is_complete = NULL;
	ctx->parent.free = digest_context_free;
	ctx->parent.set_request = digest_set_request;

	*out = (git_http_auth_context *)ctx;

	return 0;
}
