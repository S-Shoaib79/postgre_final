/*-------------------------------------------------------------------------
 *
 * am_client.h
 *	  C entry points of the Asset Access Service (AM) client
 *	  (src/backend/executor/am_client.cpp).
 *
 * The client reads am_client.conf in the data directory on every call, so
 * it can be changed without a restart.  Every call is also written to
 * am_outbox.jsonl there (method, path, tenant and the request body; never
 * the API key or the response).  See am_client.cpp for the settings.
 *
 * src/include/executor/am_client.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef AM_CLIENT_H
#define AM_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Call one AM endpoint:
 *
 *	"tenants"      POST  a tenant          (body: {"slug", "name"}; admin API)
 *	"users"        POST  a user            (body: {"username", "role", "displayName"})
 *	"roles"        POST  the role-asset matrix ({"ROLE": ["A01", ...]}; admin API)
 *	"user_assets"  GET   a user's assets and values (username in the path)
 *
 * tenant_id picks the API key (api_key.<tenant_id>, else api_key); 0 uses
 * the default key.  body may be NULL.  If response is not NULL it receives
 * the response body (free it with _PGS_AmClient_Free).
 *
 * Returns the HTTP status, 0 if AM is not configured (no url: the call is
 * only written to the outbox), or -1 on a connection error (errbuf says
 * why).
 */
extern int	_PGS_AmClient_Call(const char *endpoint, const char *username,
						  long long tenant_id, const char *body,
						  char **response, char *errbuf, int errbuflen);

extern void _PGS_AmClient_Free(char *response);

#ifdef __cplusplus
}
#endif

#endif							/* AM_CLIENT_H */
