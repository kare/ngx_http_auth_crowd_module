/*
 * Copyright (C) 2008-2010 Sergio Talens-Oliag <sto@iti.upv.es>
 *
 * Based on nginx's 'ngx_http_auth_basic_module.c' by Igor Sysoev and apache's
 * 'mod_auth_pam.c' by Ingo Luetkebolhe.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
#include <curl/curl.h>

// CROWD AUTHENTICATION

#define LOG(r) ((r)->connection->log)

static const char *CROWD_SESSION_JSON_TEMPLATE= "{\
  \"username\": \"%s\",\
  \"password\": \"%s\",\
  \"validation-factors\": {\
      \"validationFactors\": [{\
            \"name\": \"remote_address\",\
            \"value\": \"%s\"\
}]}}";

static const char *CROWD_SESSION_VALIDATE_JSON_TEMPLATE= "{\
      \"validationFactors\": [{\
            \"name\": \"remote_address\",\
            \"value\": \"%s\"\
}]}";

struct CrowdRequest {
    /* from confifuration */
    const char *server_url;
    const char *server_username;
    const char *server_password;

    /* dynamically generated */
    const char *username; /* only to basic auth */
    const char *password; /* only to basic auth */
    const char *request_url; /* request url, including server_url */
    const char *body; /* request body */
    unsigned int body_length;
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

static ngx_int_t
ngx_http_auth_crowd_get_token(ngx_http_request_t *r, ngx_str_t *token)
{
    ngx_str_t name = ngx_string("crowd.token_key");

    return  ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &name, token);
}

int parse_token_from_json(char const *s, char **token) {
    const char *START = "\"token\":\"";
    char *_token = strdup(s);
    char *t, *end;

    t = strstr(_token, START);
    if (!t) {
        return NGX_DECLINED;
    }
    end = strchr(t, ',');
    if (end) {
        *(--end) = '\0';
    }
    *token = t + strlen(START);
    return NGX_OK;
}
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
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


static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
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
void print_cookies(CURL *curl, ngx_log_t *log) {
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

int curl_transaction(struct CrowdRequest crowd_request, int expected_http_code, char **token)
{
    struct HttpRequest request;
    struct HttpResponse response;

    char error_message[CURL_ERROR_SIZE];
    char server_user_pass[128];
    const char *request_url;

    request.body = crowd_request.body;
    request.length = crowd_request.body_length;

    /* we reallocate a bigger buffer when there is data to be received */
    response.body = calloc(1, sizeof(char *));
    response.length = 0;

    request_url = crowd_request.request_url;

    CURL *curl = curl_easy_init();
    if (curl)
	return NGX_ERROR;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Transfer-Encoding: chunked");
    headers = curl_slist_append(headers, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); /* don't verify peer against cert */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); /* don't verify host against cert */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); /* bounce through login to next page */

    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_message);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &request);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "nginx-auth-agent/1.0");

    snprintf(server_user_pass, sizeof(server_user_pass), "%s:%s",
	     crowd_request.server_username, crowd_request.server_password);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, server_user_pass);

    curl_easy_setopt(curl, CURLOPT_URL, request_url);

    /* do it now */
    CURLcode curl_code = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    int error_code = NGX_OK;
    if (curl_code != 0) {
        error_code = NGX_ERROR;
    } 
    /* We return token only when we are creating it */
    if (http_code == expected_http_code) {
	if (token != NULL)
	    error_code = parse_token_from_json(response.body, token);       
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

int create_sso_session(struct CrowdRequest crowd_request, char **token)
{
    const char *url_template = "%s/crowd/rest/usermanagement/latest/session";
    char session_json[256];
    char url_buf[256];

    snprintf(session_json, sizeof(session_json), CROWD_SESSION_JSON_TEMPLATE,
	     crowd_request.username, crowd_request.password, "10.1.18.86");
    
    snprintf(url_buf, sizeof(url_buf), url_template, crowd_request.server_url);

    crowd_request.body = session_json;
    crowd_request.body_length = strlen(session_json);
    crowd_request.request_url = url_buf;

    return curl_transaction(crowd_request, 201, token);
    
}
int validate_sso_session_token(struct CrowdRequest crowd_request, const char *token)
{
    const char *url_template = "%s/crowd/rest/usermanagement/latest/session/%s";
    char session_json[256];
    char url_buf[256];

    snprintf(session_json, sizeof(session_json), CROWD_SESSION_VALIDATE_JSON_TEMPLATE,
	     "10.1.18.86");
    snprintf(url_buf, sizeof(url_buf), url_template, crowd_request.server_url, token); 

    crowd_request.body = session_json;
    crowd_request.body_length = strlen(session_json);
    crowd_request.request_url = url_buf;

    return curl_transaction(crowd_request, 200, NULL);
}
// END CROWD AUTHENTICATION

/* Module context data */
typedef struct {
    ngx_str_t  passwd;
} ngx_http_auth_crowd_ctx_t;

/* Crowd userinfo */
typedef struct {
    ngx_str_t  username;
    ngx_str_t  password;
} ngx_crowd_userinfo;

/* Module configuration struct */
typedef struct {
    ngx_str_t	realm;		/* http basic auth realm */
    ngx_str_t   crowd_url;  /* Crowd server URL */
    ngx_str_t	crowd_service;	/* Crowd service name */
    ngx_str_t   crowd_password;  /* Crowd service password */
} ngx_http_auth_crowd_loc_conf_t;

/* Module handler */
static ngx_int_t ngx_http_auth_crowd_handler(ngx_http_request_t *r);

/* Function that authenticates the user -- is the only function that uses Crowd */
static ngx_int_t ngx_http_auth_crowd_authenticate(ngx_http_request_t *r,
    ngx_http_auth_crowd_ctx_t *ctx, ngx_str_t *passwd, void *conf);

static ngx_int_t ngx_http_auth_crowd_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);

static void *ngx_http_auth_crowd_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_auth_crowd_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_auth_crowd_init(ngx_conf_t *cf);

static char *ngx_http_auth_crowd(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt  ngx_http_auth_crowd_p = ngx_http_auth_crowd;

static char *
ngx_http_auth_crowd(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

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

    { ngx_string("auth_crowd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_crowd_loc_conf_t, realm),
      &ngx_http_auth_crowd_p },

    { ngx_string("auth_crowd_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_url),
      NULL },
    { ngx_string("auth_crowd_service"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_service),
      NULL },
    { ngx_string("auth_crowd_password"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_crowd_loc_conf_t, crowd_password),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_crowd_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_crowd_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_crowd_create_loc_conf,     /* create location configuration */
    ngx_http_auth_crowd_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_auth_crowd_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_crowd_module_ctx,       /* module context */
    ngx_http_auth_crowd_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_auth_crowd_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_auth_crowd_ctx_t  *ctx;
    ngx_http_auth_crowd_loc_conf_t  *alcf;
    ngx_str_t token;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_crowd_module);

    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_crowd_module);

    if (ctx) {
        return ngx_http_auth_crowd_authenticate(r, ctx, &ctx->passwd, alcf);
    }

    /* Validate old SSO session */
    rc = ngx_http_auth_crowd_get_token(r, &token);
    if (rc != NGX_DECLINED) {
	struct CrowdRequest request;

	request.server_url = (char *) alcf->crowd_url.data;
	request.server_username = (char *) alcf->crowd_service.data;
	request.server_password = (char *) alcf->crowd_password.data;
	request.username = NULL;
	request.password = NULL;

	rc = validate_sso_session_token(request, (const char *)token.data);
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
    return ngx_http_auth_crowd_authenticate(r, ctx, &ctx->passwd, alcf);
}

void print_headers(ngx_http_request_t *r, ngx_log_t *log) {
    ngx_uint_t i;
    ngx_array_t *cookie = &r->headers_in.cookies;
    ngx_table_elt_t **elem; 
    elem = cookie->elts;
    for (i = 0; i < cookie->nelts; i++) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "'%V' -> '%V'", &elem[i]->key, &elem[i]->value);
    }
}

static ngx_int_t
ngx_http_auth_crowd_set_cookie(ngx_http_request_t *r, const char *token)
{
    const char cookie_template[] = "crowd.token_key=%s;secure";
    ngx_table_elt_t  *h;
    char *cookie;
    size_t len = sizeof(cookie_template) - 1 + strlen(token) - 2; 
    
    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
	return NGX_ERROR;
    }

    snprintf(cookie, len, cookie_template, token);

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
ngx_http_auth_crowd_authenticate(ngx_http_request_t *r,
    ngx_http_auth_crowd_ctx_t *ctx, ngx_str_t *passwd, void *conf)
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

    struct CrowdRequest request;
    request.username = (char *) uinfo.username.data;
    request.password = (char *) uinfo.password.data;
    request.server_url = (char *) alcf->crowd_url.data;
    request.server_username = (char *) alcf->crowd_service.data;
    request.server_password = (char *) alcf->crowd_password.data;

    print_headers(r, r->connection->log);

    char *token;
    int status = create_sso_session(request, &token);
    if (status == NGX_OK) {
	return ngx_http_auth_crowd_set_cookie(r, token);
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
    ngx_http_auth_crowd_loc_conf_t  *prev = parent;
    ngx_http_auth_crowd_loc_conf_t  *conf = child;

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
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_crowd_handler;

    return NGX_OK;
}
