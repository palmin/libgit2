/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_transports_auth_digest_h__
#define INCLUDE_transports_auth_digest_h__

#include "auth.h"

#if defined(GIT_OPENSSL)

extern int git_http_auth_digest(
	git_http_auth_context **out,
	const git_net_url *url);

#else

#define git_http_auth_digest git_http_auth_dummy

#endif /* GIT_OPENSSL */

#endif
