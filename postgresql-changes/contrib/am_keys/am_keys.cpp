/*-------------------------------------------------------------------------
 *
 * am_keys.cpp
 *	  The endpoint the Asset Access Service (AM) sends a signed-in user's
 *	  asset keys to; C++ part.  It runs inside PostgreSQL, in the am_keys
 *	  background worker (am_keys_worker.c), which writes the keys into
 *	  user_asset_map.asset_key.
 *
 *	POST http://127.0.0.1:<keys_port>/api/am/keys
 *	X-AM-Secret: <push_secret>
 *	Content-Type: application/json
 *	{"loginId": "...", "username": "hana.kim",
 *	 "assets": [{"name": "A01", "value": "<32-byte key, base64, 44 chars>"}]}
 *
 * This file is the part with no PostgreSQL headers (they do not compile as
 * C++ with MSVC), like am_client.cpp: the settings in am_client.conf, the
 * HTTP request, the secret check and the HTTP answer.
 *
 * Settings, read from am_client.conf in the data directory:
 *	push_secret        shared secret; empty = every push is refused (503)
 *	keys_port          listen port on 127.0.0.1 (default 7001; restart to change)
 *	keys_database      database (default erms; restart to change)
 *	keys_wait_seconds  how long to wait for the user's login (default 10)
 *
 * postgresql-changes/contrib/am_keys/am_keys.cpp
 *
 *-------------------------------------------------------------------------
 */
#include "am_keys.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace
{

std::string
trim(const std::string &s)
{
	size_t		b = s.find_first_not_of(" \t\r\n");

	if (b == std::string::npos)
		return "";
	return s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1);
}

std::string
lower(std::string s)
{
	for (auto &c : s)
		c = (char) std::tolower((unsigned char) c);
	return s;
}

void
copy_to(char *out, size_t outlen, const std::string &v)
{
	size_t		n = v.size() < outlen - 1 ? v.size() : outlen - 1;

	memcpy(out, v.data(), n);
	out[n] = '\0';
}

/* One header's value ('' if absent); head starts with the request line. */
std::string
header(const std::string &head, const char *name)
{
	std::string key = lower(std::string("\r\n") + name + ":");
	size_t		at = lower(head).find(key);

	if (at == std::string::npos)
		return "";
	size_t		start = at + key.size();
	size_t		end = head.find("\r\n", start);

	return trim(head.substr(start, end == std::string::npos ? std::string::npos : end - start));
}

}								/* namespace */

extern "C" int
_PGS_AmKeys_ParseRequest(const char *buf, int len, AmkRequest *req)
{
	std::string data(buf, len);
	size_t		header_end = data.find("\r\n\r\n");

	if (header_end == std::string::npos)
		return len > AMK_MAX_REQUEST ? -1 : 0;

	std::string head = data.substr(0, header_end);
	std::string cl = header(head, "Content-Length");
	char	   *end = nullptr;
	long		body_len = cl.empty() ? 0 : strtol(cl.c_str(), &end, 10);

	if ((!cl.empty() && *end != '\0') || body_len < 0 || body_len > AMK_MAX_REQUEST)
		return -1;
	if (data.size() < header_end + 4 + (size_t) body_len)
		return 0;

	std::string line = head.substr(0, head.find("\r\n"));
	size_t		sp1 = line.find(' ');
	size_t		sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);

	if (sp1 == std::string::npos || sp2 == std::string::npos)
		return -1;
	std::string path = line.substr(sp1 + 1, sp2 - sp1 - 1);

	memset(req, 0, sizeof(*req));
	copy_to(req->method, sizeof(req->method), line.substr(0, sp1));
	copy_to(req->path, sizeof(req->path), path.substr(0, path.find('?')));
	/* X-AM-Secret (am_stub.py), or X-Asset-Delivery-Secret (asset-access-service.jar) */
	std::string secret = header(head, "X-AM-Secret");
	if (secret.empty())
		secret = header(head, "X-Asset-Delivery-Secret");
	copy_to(req->secret, sizeof(req->secret), secret);
	copy_to(req->content_type, sizeof(req->content_type), lower(header(head, "Content-Type")));
	req->body_offset = (int) header_end + 4;
	req->body_len = (int) body_len;
	return 1;
}

extern "C" int
_PGS_AmKeys_Setting(const char *datadir, const char *name, char *out, int outlen)
{
	std::string path = std::string(datadir) + "/am_client.conf";
	FILE	   *f = fopen(path.c_str(), "r");
	char		line[1024];
	int			found = 0;

	out[0] = '\0';
	if (f == nullptr)
		return 0;
	while (fgets(line, sizeof(line), f))
	{
		std::string l = trim(line);
		size_t		eq = l.find('=');

		if (l.empty() || l[0] == '#' || eq == std::string::npos)
			continue;
		if (trim(l.substr(0, eq)) == name)
		{
			copy_to(out, (size_t) outlen, trim(l.substr(eq + 1)));
			found = 1;
		}
	}
	fclose(f);
	return found;
}

extern "C" int
_PGS_AmKeys_IntSetting(const char *datadir, const char *name, int dflt, int lo, int hi)
{
	char		v[64];
	char	   *end;
	long		n;

	if (!_PGS_AmKeys_Setting(datadir, name, v, sizeof(v)) || v[0] == '\0')
		return dflt;
	n = strtol(v, &end, 10);
	return (*end != '\0' || n < lo || n > hi) ? dflt : (int) n;
}

extern "C" int
_PGS_AmKeys_SecretOk(const char *sent, const char *secret)
{
	size_t		ls = strlen(sent), lk = strlen(secret);
	unsigned char diff = (ls == lk) ? 0 : 1;

	if (lk == 0)
		return 0;
	for (size_t i = 0; i < ls; i++)
		diff |= (unsigned char) (sent[i] ^ secret[i % lk]);
	return diff == 0;
}

extern "C" int
_PGS_AmKeys_Response(int status, const char *body, char *out, int outlen)
{
	const char *reason = status == 200 ? "OK" : status == 400 ? "Bad Request" :
		status == 401 ? "Unauthorized" : status == 404 ? "Not Found" :
		status == 405 ? "Method Not Allowed" : status == 409 ? "Conflict" :
		status == 413 ? "Payload Too Large" : status == 415 ? "Unsupported Media Type" :
		status == 503 ? "Service Unavailable" : "Internal Server Error";
	std::string r = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: " + std::to_string(strlen(body)) + "\r\n"
		"Connection: close\r\n\r\n" + body;

	if (r.size() >= (size_t) outlen)
		return -1;
	memcpy(out, r.data(), r.size());
	out[r.size()] = '\0';
	return (int) r.size();
}

extern "C" void
_PGS_AmKeys_ErrorBody(const char *code, const char *message, char *out, int outlen)
{
	copy_to(out, (size_t) outlen,
			std::string("{\"code\": \"") + code + "\", \"message\": \"" + message + "\"}");
}
