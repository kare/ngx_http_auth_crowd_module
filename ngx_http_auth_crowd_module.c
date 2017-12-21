/*
 * Copyright (C) 2013 Reaktor
 * Kare Nuorteva <kare.nuorteva@reaktor.fi>
 * Pasi Savanainen <pasi.savanainen@reaktor.fi>
 *
 * Based on nginx's 'ngx_http_auth_basic_module.c' by Igor Sysoev and apache's
 * 'mod_auth_pam.c' by Ingo Luetkebolhe and ngx_http_auth_pam_module.c by Sergio Talens-Oliag
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <curl/curl.h>

// CROWD AUTHENTICATION

/* Module context data */
typedef struct {
	char domain[128];
	char name[128];
	char secure[128];
} ngx_http_auth_crowd_ctx_t;

/* Crowd userinfo */
typedef struct {
	ngx_str_t username;
	ngx_str_t password;
} ngx_crowd_userinfo;

/* Module configuration struct */
typedef struct {
	ngx_str_t realm; /* http basic auth realm */
	ngx_str_t crowd_url; /* Crowd server URL */
	ngx_str_t crowd_service; /* Crowd service name */
	ngx_str_t crowd_password; /* Crowd service password */
} ngx_http_auth_crowd_loc_conf_t;

#define LOG(r) ((r)->connection->log)

static const char *CROWD_SESSION_JSON_TEMPLATE= "{\
	\"username\": \"%V\",\
	\"password\": \"%V\",\
	\"validation-factors\": {\
	\"validationFactors\": [{\
		\"name\": \"remote_address\",\
		\"value\": \"%V\"\
}]}}";

static const char *CROWD_SESSION_VALIDATE_JSON_TEMPLATE= "{\
	\"validationFactors\": [{\
		\"name\": \"remote_address\", \
		\"value\": \"%V\" \
}]}";

struct CrowdRequest {
	/* from confifuration */
	ngx_str_t server_username;
	ngx_str_t server_password;

	/* dynamically generated */
	ngx_str_t request_url;
	ngx_str_t body; /* request body */
	unsigned int method; /* 1 == GET */
};

struct CrowdResponse {
	int response;
	char error_message[255];
};

struct HttpResponse {
	char *body;
	size_t length;
};
struct HttpRequest {
	const char *body;
	size_t length;
};

/* Module handler */
static ngx_int_t ngx_http_auth_crowd_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_crowd_authenticate(ngx_http_request_t *r,
	ngx_http_auth_crowd_ctx_t *ctx, void *conf);

static ngx_int_t ngx_http_auth_crowd_set_realm(ngx_http_request_t *r,
	ngx_str_t *realm);

static void *ngx_http_auth_crowd_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_auth_crowd_merge_loc_conf(ngx_conf_t *cf,
	void *parent, void *child);

static ngx_int_t ngx_http_auth_crowd_init(ngx_conf_t *cf);

static char *ngx_http_auth_crowd(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt  ngx_http_auth_crowd_p = ngx_http_auth_crowd;

static ngx_int_t
ngx_http_auth_crowd_get_token(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *token)
{
	return  ngx_http_parse_multi_header_lines(&r->headers_in.cookies, name, token);
}

static int
parse_name_value(const char *json, const char *name, char *value, size_t len, char endm)
{
	/*  "name1":"value2","name2":"value2" */
	char *str = strdup(json);
	char *s, *end;
	int ec = NGX_DECLINED;

	s = strstr(str, name);
	if (!s)
		return ec;

	end = strchr(s + strlen(name), endm);
	if (end)
		*(end) = '\0';

	if (len >= (size_t)(end - (s + strlen(name)))) {
		strcpy(value, s + strlen(name));
		ec = NGX_OK;
	}

	free(str);

	return ec;
}

static int
parse_config_from_json(ngx_http_request_t *r, const char *json, ngx_http_auth_crowd_ctx_t *cc)
{
// {"domain":".my.domain.fi","secure":false,"name":"my-crowd.token_key"},
	const char *domain = "\"domain\":\"";
	const char *name   = "\"name\":\"";
	const char *secure = "\"secure\":";
	char buff[6];
	int ec1, ec2, ec3;

	ec1 = parse_name_value(json, domain, cc->domain, 128, '"');
	ec2 = parse_name_value(json, name, cc->name, 128, '"');
	ec3 = parse_name_value(json, secure, buff, 6, ',');
	if (!strcmp(buff, "true"))
		strcpy(cc->secure, "secure");

	if (ec1 != NGX_OK || ec2 != NGX_OK || ec3 != NGX_OK)
		return NGX_DECLINED;

	return NGX_OK;
}

int parse_token_from_json(ngx_http_request_t *r, char const *json, char *token, size_t len)
{
	const char *tname = "\"token\":\"";

	return parse_name_value(json, tname, token, len, '"');
}

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct HttpRequest *data = (struct HttpRequest *) userp;

	if (size * nmemb < 1)
		return 0;

	if (data->length) {
		*(char *) ptr = data->body[0];
		data->body++;
		data->length--;
		return 1;
	}
	return 0;
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct HttpResponse *response = (struct HttpResponse *) userp;

	response->body = realloc(response->body, response->length + realsize + 1);
	if (response->body == NULL) {
		perror("Out of memory.");
		return 0;
	}

	memcpy(&(response->body[response->length]), contents, realsize);
	response->length += realsize;
	response->body[response->length] = 0;

	return realsize;
}
void
print_cookies(CURL *curl, ngx_log_t *log)
{
	struct curl_slist *cookies;
	CURLcode res = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
	if (res != CURLE_OK) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "Get cookies failed: '%s'", curl_easy_strerror(res));
	}
	struct curl_slist *nc = cookies;
	int i = 1;
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "COOKIE DEBUG");
	while (nc) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "[%d]: '%s'", i, nc->data);
		nc = nc->next;
		i++;
	}
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "END COOKIE DEBUG");
	curl_slist_free_all(cookies);
}

int
curl_transaction(ngx_http_request_t *r, struct CrowdRequest *crowd_request, int expected_http_code, void *data)
{
	struct HttpRequest request;
	struct HttpResponse response;

	char error_message[CURL_ERROR_SIZE];
	u_char server_user_pass[128] = { '\0' };
	int get_config = 0; /* this is terrible */

	request.body = (char *) crowd_request->body.data;
	request.length = crowd_request->body.len;

	/* we reallocate a bigger buffer when there is data to be received */
	response.body = calloc(1, sizeof(char *));
	response.length = 0;

	CURL *curl = curl_easy_init();
	if (curl == NULL)
		return NGX_ERROR;

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json");
	if (crowd_request->method != 1)
		headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
	headers = curl_slist_append(headers, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); /* don't verify peer against cert */
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); /* don't verify host against cert */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); /* bounce through login to next page */

	if (crowd_request->method == 1) {
		get_config = 1;
	} else {
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
	}

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_message);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
	curl_easy_setopt(curl, CURLOPT_READDATA, &request);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "nginx-auth-agent/1.0");

	ngx_snprintf(server_user_pass, sizeof(server_user_pass), "%V:%V",
		 &crowd_request->server_username, &crowd_request->server_password);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	curl_easy_setopt(curl, CURLOPT_USERPWD, (char *) server_user_pass);
	curl_easy_setopt(curl, CURLOPT_URL, crowd_request->request_url.data);


	/* do it now */
	CURLcode curl_code = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	int error_code = NGX_OK;
	if (curl_code != 0) {
		error_code = NGX_ERROR;
	}

	if (http_code == expected_http_code) {
		if (data != NULL) {
			if (!get_config)
				error_code = parse_token_from_json(r, response.body, data, 128);
			else
				error_code = parse_config_from_json(r, response.body, data);
		}
		goto cleanup;
	} else {
		error_code = NGX_ERROR;
	}

cleanup:
	free(response.body);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return error_code;
}

static int
get_cookie_config(ngx_http_request_t *r, ngx_http_auth_crowd_loc_conf_t  *alcf, ngx_http_auth_crowd_ctx_t *cc)
{
	const char *url_template = "%V/rest/usermanagement/latest/config/cookie";
	u_char url_buf[256] = { '\0' };
	struct CrowdRequest request;

	ngx_snprintf(url_buf, sizeof(url_buf), url_template, &alcf->crowd_url);

	request.request_url.data = url_buf;
	request.request_url.len = ngx_strlen(url_buf);

	request.server_username = alcf->crowd_service;
	request.server_password = alcf->crowd_password;
	ngx_str_null(&request.body);
	request.method = 1;

	return curl_transaction(r, &request, 200, cc);
}

int
create_sso_session(ngx_http_request_t *r, ngx_http_auth_crowd_loc_conf_t *alcf, ngx_str_t *username,
		ngx_str_t *password, char *token)
{
	const char *url_template = "%V/rest/usermanagement/latest/session";
	u_char session_json[256] = { '\0' };
	u_char url_buf[256]= { '\0' };

	struct CrowdRequest request;
	request.server_username = alcf->crowd_service;
	request.server_password = alcf->crowd_password;

	ngx_snprintf(session_json, sizeof(session_json), CROWD_SESSION_JSON_TEMPLATE,
		username, password, &r->connection->addr_text);

	ngx_snprintf(url_buf, sizeof(url_buf), url_template, &alcf->crowd_url);

	request.body.data = session_json;
	request.body.len = ngx_strlen(session_json);
	request.request_url.data = url_buf;
	request.request_url.len = ngx_strlen(url_buf);
	request.method = 0;

	return curl_transaction(r, &request, 201, token);
}

int
validate_sso_session_token(ngx_http_request_t *r, ngx_http_auth_crowd_loc_conf_t *alcf, ngx_str_t *token)
{
	const char *url_template = "%V/rest/usermanagement/latest/session/%V";
	u_char session_json[256] = { '\0' };
	u_char url_buf[256] = { '\0' };
	struct CrowdRequest request;

	ngx_snprintf(session_json, sizeof(session_json),
			CROWD_SESSION_VALIDATE_JSON_TEMPLATE, &r->connection->addr_text);
	ngx_snprintf(url_buf, sizeof(url_buf), url_template, &alcf->crowd_url, token);

	request.body.data = session_json;
	request.body.len = ngx_strlen(session_json);
	request.request_url.data = url_buf;
	request.request_url.len = ngx_strlen(url_buf);
	request.server_username = alcf->crowd_service;
	request.server_password = alcf->crowd_password;
	request.method = 0;

	return curl_transaction(r, &request, 200, NULL);
}
// END CROWD AUTHENTICATION

static char *
ngx_http_auth_crowd(ngx_conf_t *cf, void *post, void *data)
{
	ngx_str_t *realm = data;

	size_t len;
	u_char *basic, *p;

	if (ngx_strcmp(realm->data, "off") == 0) {
		realm->len = 0;
		realm->data = (u_char *) "";

		return NGX_CONF_OK;
	}

	len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

	basic = ngx_palloc(cf->pool, len);
	if (basic == NULL) {
		return NGX_CONF_ERROR;
	}

	p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
	p = ngx_cpymem(p, realm->data, realm->len);
	*p = '"';

	realm->len = len;
	realm->data = basic;

	return NGX_CONF_OK;
}

static ngx_command_t  ngx_http_auth_crowd_commands[] = {
	{
		ngx_string("auth_crowd"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_crowd_loc_conf_t, realm),
		&ngx_http_auth_crowd_p
	},
	{
		ngx_string("auth_crowd_url"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_url),
		NULL
	},
	{
		ngx_string("auth_crowd_service"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_service),
		NULL
	},
	{
		ngx_string("auth_crowd_password"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_password),
		NULL
	},

	ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_crowd_module_ctx = {
	NULL, /* preconfiguration */
	ngx_http_auth_crowd_init, /* postconfiguration */
	NULL, /* create main configuration */
	NULL, /* init main configuration */
	NULL, /* create server configuration */
	NULL, /* merge server configuration */
	ngx_http_auth_crowd_create_loc_conf, /* create location configuration */
	ngx_http_auth_crowd_merge_loc_conf /* merge location configuration */
};

ngx_module_t  ngx_http_auth_crowd_module = {
	NGX_MODULE_V1,
	&ngx_http_auth_crowd_module_ctx, /* module context */
	ngx_http_auth_crowd_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	NULL, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_crowd_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_auth_crowd_ctx_t *ctx;
	ngx_http_auth_crowd_loc_conf_t *alcf;
	ngx_str_t token, name;

	alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_crowd_module);

	if (alcf->realm.len == 0) {
		return NGX_DECLINED;
	}

	/* Find out cookie configuration */
	ctx = ngx_http_get_module_ctx(r, ngx_http_auth_crowd_module);
	if (!ctx) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_crowd_ctx_t));
		if (ctx == NULL) {
			return NGX_ERROR;
		}

		rc = get_cookie_config(r, alcf, ctx);
		if (rc != NGX_OK) {
			return NGX_HTTP_SERVICE_UNAVAILABLE;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_auth_crowd_module);
	}

	/* Validate old SSO session */
	name.data = (u_char *) ctx->name;
	name.len = strlen(ctx->name);
	rc = ngx_http_auth_crowd_get_token(r, &name,  &token);
	if (rc != NGX_DECLINED) {
		rc = validate_sso_session_token(r, alcf, &token);
		if (rc != NGX_OK)
			return ngx_http_auth_crowd_set_realm(r, &alcf->realm);
	}

	/* Create new SSO session */
	/* Decode http auth user and passwd, leaving values on the request */
	rc = ngx_http_auth_basic_user(r);
	if (rc == NGX_DECLINED) {
		return ngx_http_auth_crowd_set_realm(r, &alcf->realm);
	}

	if (rc == NGX_ERROR) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Check user & password using Crowd */
	return ngx_http_auth_crowd_authenticate(r, ctx, alcf);
}

void
print_headers(ngx_http_request_t *r, ngx_log_t *log)
{
	ngx_uint_t i;
	ngx_array_t *cookie = &r->headers_in.cookies;
	ngx_table_elt_t **elem;
	elem = cookie->elts;

	for (i = 0; i < cookie->nelts; i++) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "'%V' -> '%V'", &elem[i]->key, &elem[i]->value);
	}
}

static ngx_int_t
ngx_http_auth_crowd_set_cookie(ngx_http_request_t *r, const char *name, const char *token,
		const char *domain, const char *secure)
{
	const char cookie_template[] = "%s=%s;domain=%s;%s";
	ngx_table_elt_t  *h;
	char *cookie;
	size_t len = sizeof(cookie_template) - 8 +
		strlen(name) + strlen(token) + strlen(domain) + strlen(secure);

	cookie = ngx_pnalloc(r->pool, len);
	if (cookie == NULL) {
		return NGX_ERROR;
	}

	snprintf(cookie, len, cookie_template, name, token, domain, secure);

	h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	h->key.data = (u_char *) "Set-Cookie";
	h->key.len = sizeof("Set-Cookie") - 1;

	h->value.data = (u_char *)cookie;
	h->value.len = len - 1;

	h->hash = 1;

	return NGX_OK;
}

static ngx_int_t
ngx_http_auth_crowd_authenticate(ngx_http_request_t *r, ngx_http_auth_crowd_ctx_t *ctx, void *conf)
{
	ngx_http_auth_crowd_loc_conf_t *alcf;

	ngx_crowd_userinfo uinfo;
	alcf = conf;

	size_t len;
	u_char *uname_buf, *p;

	/**
	 * Get username and password, note that r->headers_in.user contains the
	 * string 'user:pass', so we need to copy the username
	 **/
	for (len = 0; len < r->headers_in.user.len; len++) {
		if (r->headers_in.user.data[len] == ':') {
			break;
		}
	}

	uname_buf = ngx_palloc(r->pool, len + 1);
	if (uname_buf == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	p = ngx_cpymem(uname_buf, r->headers_in.user.data , len);
	*p ='\0';

	uinfo.username.data = uname_buf;
	uinfo.username.len = len;
	uinfo.password.data = r->headers_in.passwd.data;
	uinfo.password.len = r->headers_in.passwd.len;

	char token[128];
	int status = create_sso_session(r, alcf, &uinfo.username, &uinfo.password, token);
	if (status == NGX_OK) {
		return ngx_http_auth_crowd_set_cookie(r, ctx->name, token, ctx->domain, ctx->secure);
	}

	return ngx_http_auth_crowd_set_realm(r, &alcf->realm);
}

static ngx_int_t
ngx_http_auth_crowd_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
	r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
	if (r->headers_out.www_authenticate == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->headers_out.www_authenticate->hash = 1;
	r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
	r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
	r->headers_out.www_authenticate->value = *realm;

	return NGX_HTTP_UNAUTHORIZED;
}

static void *
ngx_http_auth_crowd_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_auth_crowd_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_crowd_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	return conf;
}

static char *
ngx_http_auth_crowd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_crowd_loc_conf_t *prev = parent;
	ngx_http_auth_crowd_loc_conf_t *conf = child;

	if (conf->realm.data == NULL) {
		conf->realm = prev->realm;
	}

	if (conf->crowd_url.data == NULL) {
		conf->crowd_url = prev->crowd_url;
	}

	if (conf->crowd_service.data == NULL) {
		conf->crowd_service = prev->crowd_service;
	}

	if (conf->crowd_password.data == NULL) {
		conf->crowd_password = prev->crowd_password;
	}

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_crowd_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_auth_crowd_handler;

	return NGX_OK;
}
