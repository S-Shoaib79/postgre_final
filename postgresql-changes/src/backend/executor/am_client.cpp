/*-------------------------------------------------------------------------
 *
 * am_client.cpp
 *	  Client of the Asset Access Service (AM), used by runtime_security.c.
 *	  Everything that leaves PostgreSQL goes through here.
 *
 * Settings: am_client.conf in the data directory, read on every call, one
 * "name = value" per line, # starts a comment:
 *
 *	url = http://127.0.0.1:8090           AM's address; empty = do not send
 *	api_key = ak_...                      default X-Api-Key
 *	api_key.<TenantID> = ak_...           X-Api-Key of one tenant
 *	timeout_ms = 5000
 *	path.tenants = /api/v1/tenants        POST a tenant
 *	path.users = /api/v1/users            POST a user
 *	path.roles = /api/v1/roles            POST the role-asset matrix
 *	path.user_assets = /api/v1/users/{username}/assets   GET at login
 *
 * The real AM (asset-access-service.jar) takes the matrix and new tenants
 * only from its platform admin, through its admin API.  Setting admin_user
 * switches "roles" and "tenants" to that API: each call signs in for a
 * token, sends it as "Authorization: Bearer", and signs out.  Users and
 * logins keep using the tenant's API key.
 *
 *	admin_user = admin                    AM's platform admin
 *	admin_password = ...
 *	tenant_admin_user = manager           first admin of each new tenant
 *	tenant_admin_password = ...           (AM refuses a tenant without one)
 *	path.admin_token = /api/admin/auth/token
 *	path.admin_logout = /api/admin/auth/logout
 *	path.roles and path.tenants then default to /api/admin/role-asset-map
 *	and /api/admin/tenants.
 *	user_password = random                AM requires a password for every
 *	                                      user; this sends a random one that
 *	                                      nobody knows.  The flow never signs
 *	                                      users in to AM: logins fetch their
 *	                                      assets with the tenant's API key.
 *
 * Every call is appended to am_outbox.jsonl in the data directory, one JSON
 * object per line: time, method, path, tenantId, status and the request
 * body.  The API key, the admin and tenant admin passwords, the admin token
 * and AM's answers (which carry the asset values) are never written.
 *
 * Only plain C crosses into PostgreSQL: no exception leaves this file and
 * nothing here calls elog.  HTTP uses WinHTTP (part of Windows).
 *
 * src/backend/executor/am_client.cpp
 *
 *-------------------------------------------------------------------------
 */
#include "executor/am_client.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <random>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace
{

const char *CONFIG_FILE = "am_client.conf";
const char *OUTBOX_FILE = "am_outbox.jsonl";
const size_t MAX_RESPONSE = 1024 * 1024;

typedef std::map<std::string, std::string> Config;

std::string
_PGS_trim(const std::string &s)
{
	size_t		b = s.find_first_not_of(" \t\r\n");
	size_t		e = s.find_last_not_of(" \t\r\n");

	return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
}

Config
_PGS_read_config()
{
	Config		cfg;
	std::ifstream in(CONFIG_FILE);
	std::string line;

	while (std::getline(in, line))
	{
		size_t		hash = line.find('#');
		size_t		eq;

		if (hash != std::string::npos)
			line.erase(hash);
		eq = line.find('=');
		if (eq != std::string::npos)
			cfg[_PGS_trim(line.substr(0, eq))] = _PGS_trim(line.substr(eq + 1));
	}
	return cfg;
}

std::string
_PGS_setting(const Config &cfg, const std::string &name, const std::string &dflt)
{
	Config::const_iterator it = cfg.find(name);

	return it == cfg.end() || it->second.empty() ? dflt : it->second;
}

/* Percent-encode a path segment ("Asset 1" -> "Asset%201") */
std::string
_PGS_url_encode(const std::string &s)
{
	static const char hex[] = "0123456789ABCDEF";
	std::string out;

	for (unsigned char c : s)
	{
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
			out += (char) c;
		else
		{
			out += '%';
			out += hex[c >> 4];
			out += hex[c & 15];
		}
	}
	return out;
}

std::string
_PGS_json_string(const std::string &s)
{
	std::string out = "\"";

	for (unsigned char c : s)
	{
		if (c == '"' || c == '\\')
		{
			out += '\\';
			out += (char) c;
		}
		else if (c < 0x20)
		{
			char		buf[8];

			snprintf(buf, sizeof(buf), "\\u%04x", c);
			out += buf;
		}
		else
			out += (char) c;
	}
	return out + "\"";
}

void
_PGS_write_outbox(const std::string &method, const std::string &path,
			 long long tenant_id, int status, const char *body)
{
	std::ofstream out(OUTBOX_FILE, std::ios::app | std::ios::binary);
	char		when[32];
	time_t		now = time(nullptr);
	struct tm	tmv;

#ifdef _WIN32
	gmtime_s(&tmv, &now);
#else
	gmtime_r(&now, &tmv);
#endif
	strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tmv);

	/* body is JSON built by PostgreSQL, so it is written as it is */
	out << "{\"time\": \"" << when << "\", \"method\": \"" << method
		<< "\", \"path\": " << _PGS_json_string(path)
		<< ", \"tenantId\": " << tenant_id
		<< ", \"status\": " << status
		<< ", \"body\": " << (body ? body : "null") << "}\n";
}

#ifdef _WIN32
std::wstring
_PGS_widen(const std::string &s)
{
	int			n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	std::wstring w(n > 0 ? n : 1, L'\0');

	if (n > 0)
		MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
	w.resize(wcslen(w.c_str()));
	return w;
}

struct Handle
{
	HINTERNET	h;
	explicit Handle(HINTERNET x) : h(x) {}
	~Handle() { if (h) WinHttpCloseHandle(h); }
};

/* The WinHTTP error, read before any handle is closed */
int
_PGS_winhttp_error(const std::string &method, const std::string &url, std::string &error)
{
	char		buf[64];

	snprintf(buf, sizeof(buf), "WinHTTP error %lu", (unsigned long) GetLastError());
	error = std::string(buf) + " calling " + method + " " + url;
	return -1;
}

/* auth is one header line without its CRLF ("X-Api-Key: ..."), or empty */
int
_PGS_http(const std::string &method, const std::string &url,
	 const std::string &auth, const char *body, int timeout_ms,
	 std::string &response, std::string &error)
{
	std::wstring wurl = _PGS_widen(url);
	URL_COMPONENTS uc;
	wchar_t		host[256];
	wchar_t		path[4096];
	DWORD		status = 0;
	DWORD		size = sizeof(status);
	std::wstring headers = L"Accept: application/json\r\n";
	DWORD		body_len = body ? (DWORD) strlen(body) : 0;

	memset(&uc, 0, sizeof(uc));
	uc.dwStructSize = sizeof(uc);
	uc.lpszHostName = host;
	uc.dwHostNameLength = 256;
	uc.lpszUrlPath = path;
	uc.dwUrlPathLength = 4096;
	if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc))
	{
		error = "bad url in am_client.conf: " + url;
		return -1;
	}

	Handle		session(WinHttpOpen(L"PostgreSQL-RuntimeSecurity/1.0",
									WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
									WINHTTP_NO_PROXY_NAME,
									WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session.h)
		return _PGS_winhttp_error(method, url, error);
	WinHttpSetTimeouts(session.h, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

	Handle		connect(WinHttpConnect(session.h, host, uc.nPort, 0));
	if (!connect.h)
		return _PGS_winhttp_error(method, url, error);

	Handle		request(WinHttpOpenRequest(connect.h, _PGS_widen(method).c_str(), path,
										   nullptr, WINHTTP_NO_REFERER,
										   WINHTTP_DEFAULT_ACCEPT_TYPES,
										   uc.nScheme == INTERNET_SCHEME_HTTPS ?
										   WINHTTP_FLAG_SECURE : 0));
	if (!request.h)
		return _PGS_winhttp_error(method, url, error);

	if (!auth.empty())
		headers += _PGS_widen(auth) + L"\r\n";
	if (body)
		headers += L"Content-Type: application/json\r\n";

	if (!WinHttpSendRequest(request.h, headers.c_str(), (DWORD) -1L,
							body ? (LPVOID) body : WINHTTP_NO_REQUEST_DATA,
							body_len, body_len, 0) ||
		!WinHttpReceiveResponse(request.h, nullptr) ||
		!WinHttpQueryHeaders(request.h,
							 WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
							 WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
							 WINHTTP_NO_HEADER_INDEX))
		return _PGS_winhttp_error(method, url, error);

	for (;;)
	{
		DWORD		avail = 0;
		DWORD		got = 0;
		char		buf[8192];

		if (!WinHttpQueryDataAvailable(request.h, &avail))
			return _PGS_winhttp_error(method, url, error);
		if (avail == 0)
			break;
		if (avail > sizeof(buf))
			avail = sizeof(buf);
		if (!WinHttpReadData(request.h, buf, avail, &got))
			return _PGS_winhttp_error(method, url, error);
		if (got == 0)
			break;
		if (response.size() + got > MAX_RESPONSE)
		{
			error = "AM's answer is too large";
			return -1;
		}
		response.append(buf, got);
	}
	return (int) status;
}
#else
int
_PGS_http(const std::string &, const std::string &, const std::string &,
	 const char *, int, std::string &, std::string &error)
{
	error = "the AM client is only built for Windows (WinHTTP)";
	return -1;
}
#endif

/*
 * The text of a string field in a JSON answer ("accessToken": "..."), or
 * empty.  AM's answers are small and well formed; this is not a general
 * JSON parser.
 */
std::string
_PGS_json_text(const std::string &json, const std::string &field)
{
	size_t		at = json.find("\"" + field + "\"");
	std::string out;

	if (at == std::string::npos)
		return out;
	at = json.find(':', at + field.size() + 2);
	if (at == std::string::npos)
		return out;
	at = json.find_first_not_of(" \t\r\n", at + 1);
	if (at == std::string::npos || json[at] != '"')
		return out;
	for (size_t i = at + 1; i < json.size(); i++)
	{
		if (json[i] == '"')
			return out;
		if (json[i] == '\\')
			return std::string();	/* escapes never occur in a token */
		out += json[i];
	}
	return std::string();
}

/*
 * One call to AM's admin API: sign in as the platform admin, make the call
 * with the token, sign out.  Returns the call's HTTP status, or the sign-in's
 * if that failed (answer then holds AM's reason), or -1.
 */
int
_PGS_admin_http(const Config &cfg, const std::string &url,
				const std::string &method, const std::string &path,
				const char *body, int timeout_ms,
				std::string &answer, std::string &error)
{
	std::string login = "{\"username\": " + _PGS_json_string(_PGS_setting(cfg, "admin_user", "")) +
		", \"password\": " + _PGS_json_string(_PGS_setting(cfg, "admin_password", "")) + "}";
	std::string token;
	std::string ignored;
	std::string ignored_error;
	int			status;

	status = _PGS_http("POST", url + _PGS_setting(cfg, "path.admin_token", "/api/admin/auth/token"),
					   "", login.c_str(), timeout_ms, answer, error);
	if (status != 200)
		return status;
	token = _PGS_json_text(answer, "accessToken");
	answer.clear();
	if (token.empty())
	{
		error = "AM's sign-in answer has no accessToken";
		return -1;
	}

	status = _PGS_http(method, url + path, "Authorization: Bearer " + token,
					   body, timeout_ms, answer, error);

	/* the token would expire on its own; ending it now is tidier */
	_PGS_http("POST", url + _PGS_setting(cfg, "path.admin_logout", "/api/admin/auth/logout"),
			  "Authorization: Bearer " + token, nullptr, timeout_ms, ignored, ignored_error);
	return status;
}

/* body (a JSON object) with one more field: "name": value (value is JSON) */
std::string
_PGS_with_field(const char *body, const std::string &name, const std::string &value)
{
	std::string out = body ? body : "{}";
	size_t		end = out.find_last_of('}');

	if (end == std::string::npos)
		return out;
	return out.substr(0, end) + ", " + _PGS_json_string(name) + ": " + value + "}";
}

/*
 * A new tenant for AM's admin API: PostgreSQL's {"slug", "name"} plus the
 * tenant's first admin from am_client.conf, which AM requires.
 */
std::string
_PGS_with_tenant_admin(const Config &cfg, const char *body)
{
	return _PGS_with_field(body, "admin",
						   "{\"username\": " + _PGS_json_string(_PGS_setting(cfg, "tenant_admin_user", "")) +
						   ", \"password\": " + _PGS_json_string(_PGS_setting(cfg, "tenant_admin_password", "")) + "}");
}

/*
 * 32 random letters and digits.  std::random_device is the operating
 * system's secure generator on Windows (rand_s).
 */
std::string
_PGS_random_password()
{
	static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	std::random_device rd;
	std::string out;

	while (out.size() < 32)
	{
		unsigned int r = rd() & 63;

		if (r < 62)				/* no modulo bias */
			out += chars[r];
	}
	return out;
}

}								/* namespace */

extern "C" int
_PGS_AmClient_Call(const char *endpoint, const char *username, long long tenant_id,
			  const char *body, char **response, char *errbuf, int errbuflen)
{
	if (response)
		*response = nullptr;
	if (errbuf && errbuflen > 0)
		errbuf[0] = '\0';

	try
	{
		Config		cfg = _PGS_read_config();
		std::string ep = endpoint ? endpoint : "";
		std::string method = ep == "user_assets" ? "GET" : "POST";
		std::string path;
		std::string url = _PGS_setting(cfg, "url", "");
		std::string api_key;
		std::string answer;
		std::string error;
		int			timeout_ms = atoi(_PGS_setting(cfg, "timeout_ms", "5000").c_str());
		int			status;

		/* the matrix and new tenants go to AM's admin API when one is set */
		bool		admin = (ep == "tenants" || ep == "roles") &&
			!_PGS_setting(cfg, "admin_user", "").empty();

		if (ep == "tenants")
			path = _PGS_setting(cfg, "path.tenants",
								admin ? "/api/admin/tenants" : "/api/v1/tenants");
		else if (ep == "users")
			path = _PGS_setting(cfg, "path.users", "/api/v1/users");
		else if (ep == "roles")
			path = _PGS_setting(cfg, "path.roles",
								admin ? "/api/admin/role-asset-map" : "/api/v1/roles");
		else if (ep == "user_assets")
		{
			size_t		at;

			std::string user = username ? username : "";

			/*
			 * url_encode leaves dots alone and URL parsing collapses "." and
			 * "..", so a user named ".." would turn /users/../assets into
			 * /assets: another endpoint.
			 */
			if (user.empty() || user == "." || user == "..")
			{
				snprintf(errbuf, errbuflen, "\"%s\" is not a valid username for AM", user.c_str());
				return -1;
			}
			path = _PGS_setting(cfg, "path.user_assets", "/api/v1/users/{username}/assets");
			at = path.find("{username}");
			if (at != std::string::npos)
				path.replace(at, 10, _PGS_url_encode(user));
			body = nullptr;
		}
		else
		{
			snprintf(errbuf, errbuflen, "unknown AM endpoint \"%s\"", ep.c_str());
			return -1;
		}

		if (url.empty())
		{
			_PGS_write_outbox(method, path, tenant_id, 0, body);
			return 0;
		}
		while (!url.empty() && url.back() == '/')
			url.pop_back();

		if (admin)
		{
			std::string sent = ep == "tenants" ? _PGS_with_tenant_admin(cfg, body) : body ? body : "";

			status = _PGS_admin_http(cfg, url, method, path, sent.c_str(), timeout_ms,
									 answer, error);
		}
		else
		{
			std::string sent = body ? body : "";

			if (ep == "users" && _PGS_setting(cfg, "user_password", "") == "random")
				sent = _PGS_with_field(body, "password", _PGS_json_string(_PGS_random_password()));
			api_key = _PGS_setting(cfg, "api_key." + std::to_string(tenant_id),
							  _PGS_setting(cfg, "api_key", ""));
			status = _PGS_http(method, url + path,
						  api_key.empty() ? "" : "X-Api-Key: " + api_key,
						  body ? sent.c_str() : nullptr,
						  timeout_ms, answer, error);
		}
		/* PostgreSQL's body only: never a password */
		_PGS_write_outbox(method, path, tenant_id, status, body);

		if (status < 0)
		{
			snprintf(errbuf, errbuflen, "%s", error.c_str());
			return -1;
		}
		if (response)
		{
			*response = (char *) malloc(answer.size() + 1);
			if (*response)
				memcpy(*response, answer.c_str(), answer.size() + 1);
		}
		return status;
	}
	catch (...)
	{
		if (errbuf && errbuflen > 0)
			snprintf(errbuf, errbuflen, "internal error in the AM client");
		return -1;
	}
}

extern "C" void
_PGS_AmClient_Free(char *response)
{
	free(response);
}
