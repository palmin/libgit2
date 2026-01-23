/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "auth_digest.h"

#include "common.h"
#include "str.h"
#include "auth.h"
#include "git2/sys/credential.h"
#include "net.h"

#ifdef GIT_OPENSSL

#include <openssl/evp.h>
#include <openssl/rand.h>

#define MD5_DIGEST_LENGTH 16
#define MD5_HEX_LENGTH    (MD5_DIGEST_LENGTH * 2)

typedef struct {
	git_http_auth_context parent;

	/* parsed from the server challenge */
	char *realm;
	char *nonce;
	char *opaque;
	char *algorithm;
	char *qop;

	/* client state */
	char *cnonce;
	unsigned int nc;
} http_auth_digest_context;

static void md5_hex(char *out, const unsigned char *data, size_t len)
{
	unsigned char digest[MD5_DIGEST_LENGTH];
	EVP_MD_CTX *ctx;
	unsigned int digest_len = MD5_DIGEST_LENGTH;
	int i;

	ctx = EVP_MD_CTX_new();
	if (ctx) {
		EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
		EVP_DigestUpdate(ctx, data, len);
		EVP_DigestFinal_ex(ctx, digest, &digest_len);
		EVP_MD_CTX_free(ctx);
	} else {
		memset(digest, 0, MD5_DIGEST_LENGTH);
	}

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		p_snprintf(out + i * 2, 3, "%02x", digest[i]);
}

static void md5_hex_str(char *out, const char *str)
{
	md5_hex(out, (const unsigned char *)str, strlen(str));
}

static int generate_cnonce(char **out)
{
	unsigned char raw[16];
	char *cnonce;
	int i;

	if (RAND_bytes(raw, sizeof(raw)) != 1) {
		git_error_set(GIT_ERROR_OS, "failed to generate random bytes");
		return -1;
	}

	cnonce = git__malloc(sizeof(raw) * 2 + 1);
	GIT_ERROR_CHECK_ALLOC(cnonce);

	for (i = 0; i < (int)sizeof(raw); i++)
		p_snprintf(cnonce + i * 2, 3, "%02x", raw[i]);

	*out = cnonce;
	return 0;
}

/*
 * Parse a key="value" or key=value pair from the challenge string.
 * Advances *scan past the parsed pair and any trailing comma/whitespace.
 */
static int parse_pair(char **key_out, char **value_out, const char **scan)
{
	const char *p = *scan;
	const char *key_start, *key_end;
	const char *val_start, *val_end;
	char *key, *value;
	bool quoted = false;

	/* skip leading whitespace */
	while (*p == ' ' || *p == '\t')
		p++;

	if (!*p)
		return GIT_ITEROVER;

	/* parse key */
	key_start = p;
	while (*p && *p != '=' && *p != ' ' && *p != '\t')
		p++;
	key_end = p;

	if (key_start == key_end || *p != '=')
		return GIT_ITEROVER;
	p++; /* skip '=' */

	/* parse value */
	if (*p == '"') {
		quoted = true;
		p++;
		val_start = p;
		while (*p && *p != '"') {
			if (*p == '\\' && *(p + 1))
				p++; /* skip escaped char */
			p++;
		}
		val_end = p;
		if (*p == '"')
			p++;
	} else {
		val_start = p;
		while (*p && *p != ',' && *p != ' ' && *p != '\t')
			p++;
		val_end = p;
	}

	/* skip trailing comma and whitespace */
	while (*p == ',' || *p == ' ' || *p == '\t')
		p++;

	*scan = p;

	/* allocate key */
	key = git__strndup(key_start, key_end - key_start);
	GIT_ERROR_CHECK_ALLOC(key);

	/* allocate value, handling backslash escapes in quoted strings */
	if (quoted) {
		size_t val_len = val_end - val_start;
		char *dst;

		value = git__malloc(val_len + 1);
		GIT_ERROR_CHECK_ALLOC(value);

		dst = value;
		p = val_start;
		while (p < val_end) {
			if (*p == '\\' && (p + 1) < val_end) {
				p++;
			}
			*dst++ = *p++;
		}
		*dst = '\0';
	} else {
		value = git__strndup(val_start, val_end - val_start);
		GIT_ERROR_CHECK_ALLOC(value);
	}

	*key_out = key;
	*value_out = value;
	return 0;
}

static int digest_set_challenge(
	git_http_auth_context *c,
	const char *challenge)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;
	const char *scan;
	char *key = NULL, *value = NULL;
	int error;

	GIT_ASSERT_ARG(ctx);
	GIT_ASSERT_ARG(challenge);

	/* free previous challenge data */
	git__free(ctx->realm);  ctx->realm = NULL;
	git__free(ctx->nonce);  ctx->nonce = NULL;
	git__free(ctx->opaque); ctx->opaque = NULL;
	git__free(ctx->algorithm); ctx->algorithm = NULL;
	git__free(ctx->qop);    ctx->qop = NULL;
	git__free(ctx->cnonce); ctx->cnonce = NULL;
	ctx->nc = 0;

	/* skip "Digest " prefix */
	if (!git__prefixncmp(challenge, strlen(challenge), "Digest"))
		scan = challenge + strlen("Digest");
	else
		scan = challenge;

	/* skip whitespace after prefix */
	while (*scan == ' ' || *scan == '\t')
		scan++;

	while ((error = parse_pair(&key, &value, &scan)) == 0) {
		if (!strcasecmp(key, "realm")) {
			git__free(ctx->realm);
			ctx->realm = value;
			value = NULL;
		} else if (!strcasecmp(key, "nonce")) {
			git__free(ctx->nonce);
			ctx->nonce = value;
			value = NULL;
		} else if (!strcasecmp(key, "opaque")) {
			git__free(ctx->opaque);
			ctx->opaque = value;
			value = NULL;
		} else if (!strcasecmp(key, "algorithm")) {
			git__free(ctx->algorithm);
			ctx->algorithm = value;
			value = NULL;
		} else if (!strcasecmp(key, "qop")) {
			git__free(ctx->qop);
			ctx->qop = value;
			value = NULL;
		}

		git__free(key);
		git__free(value);
		key = NULL;
		value = NULL;
	}

	git__free(key);
	git__free(value);

	if (!ctx->realm || !ctx->nonce) {
		git_error_set(GIT_ERROR_NET, "digest challenge missing realm or nonce");
		return -1;
	}

	return 0;
}

/*
 * Choose qop to use from the server's offered list.
 * The qop challenge value may be a comma-separated list like "auth,auth-int".
 * We only support "auth".
 */
static bool qop_includes_auth(const char *qop)
{
	const char *p = qop;
	size_t len;

	while (*p) {
		while (*p == ' ' || *p == ',')
			p++;
		len = 0;
		while (p[len] && p[len] != ',' && p[len] != ' ')
			len++;
		if (len == 4 && !strncasecmp(p, "auth", 4))
			return true;
		p += len;
	}

	return false;
}

static int digest_next_token(
	git_str *out,
	git_http_auth_context *c,
	git_credential *cred)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;
	git_credential_userpass_plaintext *userpass;
	git_str uri_buf = GIT_STR_INIT;
	git_str a1_input = GIT_STR_INIT;
	git_str a2_input = GIT_STR_INIT;
	git_str response_input = GIT_STR_INIT;
	char ha1[MD5_HEX_LENGTH + 1];
	char ha2[MD5_HEX_LENGTH + 1];
	char response[MD5_HEX_LENGTH + 1];
	char nc_str[9];
	const char *method_str;
	bool use_qop = false;
	int error = GIT_EAUTH;

	GIT_ASSERT_ARG(out);
	GIT_ASSERT_ARG(ctx);
	GIT_ASSERT_ARG(cred);

	if (cred->credtype != GIT_CREDENTIAL_USERPASS_PLAINTEXT) {
		git_error_set(GIT_ERROR_INVALID, "invalid credential type for digest auth");
		goto done;
	}

	if (!ctx->nonce || !ctx->realm) {
		git_error_set(GIT_ERROR_NET, "digest authentication not properly initialized");
		goto done;
	}

	if (!c->request_url || !c->request_method) {
		git_error_set(GIT_ERROR_NET, "digest authentication requires request info");
		goto done;
	}

	userpass = (git_credential_userpass_plaintext *)cred;
	method_str = c->request_method;

	/* determine if we should use qop */
	if (ctx->qop && qop_includes_auth(ctx->qop))
		use_qop = true;

	/* generate cnonce if needed */
	if (use_qop && !ctx->cnonce) {
		if (generate_cnonce(&ctx->cnonce) < 0)
			goto done;
	}

	/* increment nonce count */
	ctx->nc++;
	p_snprintf(nc_str, sizeof(nc_str), "%08x", ctx->nc);

	/* build the URI from the request URL path + query */
	git_net_url_fmt_path(&uri_buf, c->request_url);
	if (git_str_oom(&uri_buf))
		goto done;

	/* compute HA1 = MD5(username:realm:password) */
	git_str_printf(&a1_input, "%s:%s:%s",
		userpass->username, ctx->realm, userpass->password);
	if (git_str_oom(&a1_input))
		goto done;
	md5_hex_str(ha1, a1_input.ptr);

	/* compute HA2 = MD5(method:uri) */
	git_str_printf(&a2_input, "%s:%s", method_str, uri_buf.ptr);
	if (git_str_oom(&a2_input))
		goto done;
	md5_hex_str(ha2, a2_input.ptr);

	/* compute response digest */
	if (use_qop) {
		/* response = MD5(HA1:nonce:nc:cnonce:qop:HA2) */
		git_str_printf(&response_input, "%s:%s:%s:%s:%s:%s",
			ha1, ctx->nonce, nc_str, ctx->cnonce, "auth", ha2);
	} else {
		/* response = MD5(HA1:nonce:HA2) */
		git_str_printf(&response_input, "%s:%s:%s",
			ha1, ctx->nonce, ha2);
	}
	if (git_str_oom(&response_input))
		goto done;
	md5_hex_str(response, response_input.ptr);

	/* format the Authorization header value */
	git_str_printf(out,
		"Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
		userpass->username, ctx->realm, ctx->nonce, uri_buf.ptr, response);

	if (use_qop)
		git_str_printf(out, ", qop=auth, nc=%s, cnonce=\"%s\"", nc_str, ctx->cnonce);

	if (ctx->opaque)
		git_str_printf(out, ", opaque=\"%s\"", ctx->opaque);

	if (ctx->algorithm)
		git_str_printf(out, ", algorithm=%s", ctx->algorithm);

	if (git_str_oom(out))
		goto done;

	error = 0;

done:
	/* zero sensitive data before freeing */
	if (a1_input.size)
		git__memzero(a1_input.ptr, a1_input.size);
	if (response_input.size)
		git__memzero(response_input.ptr, response_input.size);

	git_str_dispose(&uri_buf);
	git_str_dispose(&a1_input);
	git_str_dispose(&a2_input);
	git_str_dispose(&response_input);
	return error;
}

static void digest_context_free(git_http_auth_context *c)
{
	http_auth_digest_context *ctx = (http_auth_digest_context *)c;

	git__free(ctx->realm);
	git__free(ctx->nonce);
	git__free(ctx->opaque);
	git__free(ctx->algorithm);
	git__free(ctx->qop);
	git__free(ctx->cnonce);
	git__free(ctx);
}

int git_http_auth_digest(
	git_http_auth_context **out,
	const git_net_url *url)
{
	http_auth_digest_context *ctx;

	GIT_UNUSED(url);

	*out = NULL;

	ctx = git__calloc(1, sizeof(http_auth_digest_context));
	GIT_ERROR_CHECK_ALLOC(ctx);

	ctx->parent.type = GIT_HTTP_AUTH_DIGEST;
	ctx->parent.credtypes = GIT_CREDENTIAL_USERPASS_PLAINTEXT;
	ctx->parent.connection_affinity = 0;
	ctx->parent.set_challenge = digest_set_challenge;
	ctx->parent.next_token = digest_next_token;
	ctx->parent.is_complete = NULL;
	ctx->parent.free = digest_context_free;

	*out = (git_http_auth_context *)ctx;
	return 0;
}

#endif /* GIT_OPENSSL */
