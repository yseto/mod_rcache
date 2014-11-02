#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "http_log.h"
#include "apr_strings.h"
#include "http_request.h"
#include <assert.h>
#include <curl/curl.h>
#include <hiredis/hiredis.h>
#include <unistd.h>

typedef struct {
    char*   data;
    request_rec* r;
} rcache_info;

static size_t rcache_curl_write_cb(const void* ptr, size_t size, size_t nmemb, void* _info)
{
    rcache_info* info = _info;
    if (nmemb == 0) return 0;
    const char* tmp = apr_pstrndup(info->r->pool, ptr, size * nmemb);
    info->data = apr_pstrcat(info->r->pool, info->data, tmp, NULL);
    return nmemb;
}

static size_t rcache_curl_header_cb(const void* ptr, size_t size, size_t nmemb, void* _info)
{
    rcache_info* info = _info;
    apr_time_t current_time = apr_time_now();
    if (strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.") - 1) == 0) {
        int minor_ver, status;
        if (sscanf(ptr, "HTTP/1.%d %d ", &minor_ver, &status) == 2 && status != 200)
            info->r->status = status;
    } else if (strncasecmp(ptr, "content-type:", sizeof("content-type:") - 1) == 0) {
        const char* s = (const char*)ptr + sizeof("content-type:") - 1,
              * e = (const char*)ptr + size * nmemb - 1;
        for (; s <= e; --e)
            if (*e != '\r' && *e != '\n')
                break;
        for (; s <= e; ++s)
            if (*s != ' ' && *s != '\t')
                break;
        if (s <= e)
            ap_set_content_type(info->r, apr_pstrndup(info->r->pool, s, e - s + 1));
    } else if (strncasecmp(ptr, "content-length:", sizeof("content-length:") - 1) == 0) {
        const char* s = (const char*)ptr + sizeof("content-length:") - 1,
              * e = (const char*)ptr + size * nmemb - 1;
        for (; s <= e; --e)
            if (*e != '\r' && *e != '\n')
                break;
        for (; s <= e; ++s)
            if (*s != ' ' && *s != '\t')
                break;
        if (s <= e)
            ap_set_content_length(info->r, atoi(apr_pstrndup(info->r->pool, s, e - s + 1)));
    }
    ap_update_mtime(info->r, current_time);
    ap_set_last_modified(info->r);

    return nmemb;
}

static int rcache_curl(const char *retrieve_url, void* _info)
{
    rcache_info* info = _info;
    CURL* curl = curl_easy_init();
    CURLcode ret;
    if (curl == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    curl_easy_setopt(curl, CURLOPT_URL, retrieve_url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, _info);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, rcache_curl_header_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, _info);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rcache_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, apr_psprintf(info->r->pool, "mod_rcache/%s", curl_version()));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (ret != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, info->r->server,
                "rcache: libcurl returned error (%d) while trying to retrieve url: %s",
                ret, retrieve_url);
        info->r->status = HTTP_INTERNAL_SERVER_ERROR;
    }
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, info->r->server, "%d", info->r->status );
#endif
    return info->r->status;
}
/* The sample content handler */
static int rcache_handler(request_rec *r)
{
    rcache_info info;
    info.data = "";
    info.r = r;
    apr_status_t rv;
    const char *retrieve_url;

    if (strcmp(r->handler, "rcache")) {
        return DECLINED;
    }

    // connect redis
    redisContext *c;
    redisReply *reply;
    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (c == NULL || c->err) {
        if (c) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Connection error: %s", c->errstr);
            redisFree(c);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Connection error: can't allocate redis context" );
        }
        rv = HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

    int wait = 0;

    if ( (retrieve_url = apr_table_get(r->subprocess_env, "ENVTEST")) ) {

        // WAIT flag check.
        reply = redisCommand(c, "GET WAIT::%s", retrieve_url);
        if( reply->type !=  REDIS_REPLY_NIL ) {
            wait = 1;
            int loop = 10;
            while(loop){
                reply = redisCommand(c, "GET WAIT::%s", retrieve_url);
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%d", loop);
                if( reply->type ==  REDIS_REPLY_NIL ) {
                    goto read;
                }
                sleep(1);
                loop--;
            }
            // when timeup. delete flag.
            redisCommand(c, "DEL WAIT::%s", retrieve_url);
            goto gencache;
        }
read:

        reply = redisCommand(c, "HMGET %s CONTENT TYPE LENGTH MTIME", retrieve_url);
        if( reply->type ==  REDIS_REPLY_ARRAY ) {
            if ( reply->element[0]->len == 0 ) goto gencache;
            if (!r->header_only)
                ap_rputs(reply->element[0]->str, r);

            const char* tmp = apr_psprintf(r->pool, "%s", reply->element[1]->str);
            ap_set_content_type(r, tmp);
            ap_set_content_length(r, atoi(reply->element[2]->str) );
            apr_time_t time = atol(reply->element[3]->str);
            ap_update_mtime(r, time);
            ap_set_last_modified(r);


            rv = OK;
            goto finish;
        }
    }else{
        rv = DECLINED;
        goto finish;
    }

gencache:

    if(wait == 0)
        redisCommand(c, "SET WAIT::%s 1", retrieve_url);

    rv = rcache_curl(retrieve_url, &info);
#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "azz");
#endif

    if (rv == HTTP_OK) {
        redisCommand(c,"HMSET %s CONTENT %s TYPE %s LENGTH %d MTIME %ld",
                retrieve_url, info.data, r->content_type, r->clength, r->mtime);
        redisCommand(c, "DEL WAIT::%s", retrieve_url);
    }

    if (!r->header_only)
        ap_rputs(info.data, r);

finish:
    freeReplyObject(reply);
    redisFree(c);

    return rv;
}

static void rcache_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(rcache_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA rcache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,   /* create per-dir    config structures */
    NULL,   /* merge  per-dir    config structures */
    NULL,   /* create per-server config structures */
    NULL,   /* merge  per-server config structures */
    NULL,   /* table of config file commands       */
    rcache_register_hooks   /* register hooks      */
};

