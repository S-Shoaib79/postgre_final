/*-------------------------------------------------------------------------
 *
 * am_keys.h
 *	  C entry points of the AM keys endpoint's C++ part (am_keys.cpp):
 *	  settings, the HTTP request and the HTTP answer.  The PostgreSQL side
 *	  (background worker, socket loop, writing user_asset_map) is in
 *	  am_keys_worker.c, which is the only file that includes PostgreSQL
 *	  headers.
 *
 * postgresql-changes/contrib/am_keys/am_keys.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef AM_KEYS_H
#define AM_KEYS_H

#ifdef __cplusplus
extern "C"
{
#endif

#define AMK_PATH			"/api/am/keys"
#define AMK_MAX_REQUEST		(64 * 1024)

/* One parsed HTTP request (fields cut to their size). */
typedef struct AmkRequest
{
	char		method[16];
	char		path[256];
	char		secret[512];		/* X-AM-Secret */
	char		content_type[128];
	int			body_offset;		/* the body is buf[body_offset .. +body_len] */
	int			body_len;
} AmkRequest;

/*
 * Looks at the bytes read so far.  Returns 1 when the whole request (headers
 * and Content-Length bytes of body) is there and fills req, 0 if more bytes
 * are needed, -1 if the request is too large or not HTTP.
 */
extern int	_PGS_AmKeys_ParseRequest(const char *buf, int len, AmkRequest *req);

/*
 * One "key = value" setting of <datadir>/am_client.conf into out (empty if
 * missing).  Returns 1 if found.
 */
extern int	_PGS_AmKeys_Setting(const char *datadir, const char *name, char *out, int outlen);

/* Integer setting in [lo, hi], else dflt. */
extern int	_PGS_AmKeys_IntSetting(const char *datadir, const char *name, int dflt, int lo, int hi);

/* Constant-time comparison; false if the secret is empty. */
extern int	_PGS_AmKeys_SecretOk(const char *sent, const char *secret);

/*
 * The full HTTP answer (status line, headers, body) into out.  Returns its
 * length, or -1 if out is too small.
 */
extern int	_PGS_AmKeys_Response(int status, const char *body, char *out, int outlen);

/* {"code": ..., "message": ...} into out (both plain ASCII without quotes). */
extern void _PGS_AmKeys_ErrorBody(const char *code, const char *message, char *out, int outlen);

#ifdef __cplusplus
}
#endif

#endif							/* AM_KEYS_H */
