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
    char*   type;
    int     length;
    apr_time_t mtime;

    request_rec* r;
    redisContext* c;
    redisReply *reply;
    char*   hostname;
    int     port;
} rcache_info;

//#define DEBUG

extern module AP_MODULE_DECLARE_DATA rcache_module ;

static void *create_config(apr_pool_t *pool, server_rec *s)
{
    rcache_info *info = apr_pcalloc(pool, sizeof(rcache_info));
    info->hostname = apr_pstrdup(pool, "127.0.0.1");
    info->port = 6379;
    return info;
}

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
    if (strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.") - 1) == 0) {
        int minor_ver, status;
        if (sscanf(ptr, "HTTP/1.%d %d ", &minor_ver, &status) == 2 && (status != 200 || status != 301 || status != 302) )
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
            info->type = apr_pstrndup(info->r->pool, s, e - s + 1);
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
            info->length = atoi( apr_pstrndup(info->r->pool, s, e - s + 1) );
    }
    info->mtime = apr_time_now();
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
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);
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

/* The content handler */
static int rcache_handler(request_rec *r)
{
    rcache_info *info;
    info = ap_get_module_config(r->server->module_config, &rcache_module);
    info->data = "";
    info->r = r;
    info->length = 0;
    info->type = "";

    apr_status_t rv;
    const char *retrieve_url;

    if (strcmp(r->handler, "rcache")) {
        rv = DECLINED;
        goto finish;
    }

    // redis context
    redisContext *c = info->c;
    redisReply *reply = info->reply;

    // redis connection
    if (!c) {
        struct timeval timeout = { 1, 500000 }; // 1.5 seconds
        c = redisConnectWithTimeout(info->hostname, info->port, timeout);
        info->c = c;

        // ping pong test
        if ( !(c == NULL || c->err) ) {
            reply = redisCommand(c,"PING");
#ifdef DEBUG
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "PING: %s", reply->str);
#endif
        }
    }

    // when redis connection error
    if (c == NULL || c->err) {
        if (c) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Connection error: %s", c->errstr);
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Connection error: can't allocate redis context" );
        }
        rv = HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

    int wait = 0;

    if ( (retrieve_url = apr_table_get(r->subprocess_env, "ENVTEST")) ) {

#ifdef DEBUG
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", r->path_info);
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", retrieve_url);
#endif

        // WAIT flag check.
        reply = redisCommand(c, "GET WAIT::%s", r->path_info);
        if( reply->type !=  REDIS_REPLY_NIL ) {
            wait = 1;
            int loop = 10;
            while(loop){
                reply = redisCommand(c, "GET WAIT::%s", r->path_info);
#ifdef DEBUG
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "wait loop: remain %d sec", loop);
#endif
                if( reply->type ==  REDIS_REPLY_NIL ) {
                    goto read;
                }
                sleep(1);
                loop--;
            }
            // when timeup. delete flag.
            redisCommand(c, "DEL WAIT::%s", r->path_info);
            goto gencache;
        }

read:
        // read from redis.
        reply = redisCommand(c, "HMGET %s CONTENT TYPE LENGTH MTIME", r->path_info);
        if( reply->type ==  REDIS_REPLY_ARRAY ) {
            if ( reply->element[0]->len == 0 ) goto gencache;

            const char* tmp = apr_pstrdup(r->pool, reply->element[1]->str);
            ap_set_content_type(r, tmp);
            ap_set_content_length(r, atoi(reply->element[2]->str) );
            apr_time_t time = atol(reply->element[3]->str);
            ap_update_mtime(r, time);
            ap_set_last_modified(r);
            ap_set_etag(r);

            apr_status_t rc = ap_meets_conditions(r);
            if (rc != OK) {
                rv = rc;
                goto finish;
            }

            if (!r->header_only)
                ap_rputs(reply->element[0]->str, r);

            rv = OK;
            goto finish;
        }
    }else{
        rv = DECLINED;
        goto finish;
    }

gencache:

    if (wait == 0)
        redisCommand(c, "SET WAIT::%s 1", r->path_info);

    rv = rcache_curl(retrieve_url, info);

    // set content to redis
    if (rv == HTTP_OK) {
        if (strcmp(info->type,""))
            info->type = "text/html";

        if (info->length == 0)
            info->length = strlen(info->data);

        redisCommand(c,"HMSET %s CONTENT %s TYPE %s LENGTH %d MTIME %ld",
                r->path_info, info->data, info->type, info->length, info->mtime);

        ap_set_content_type(r, info->type);
        ap_set_content_length(r, info->length);
        ap_update_mtime(r, info->mtime);
        ap_set_last_modified(r);
        ap_set_etag(r);

        if (!r->header_only)
            ap_rputs(info->data, r);
    }
    redisCommand(c, "DEL WAIT::%s", r->path_info);

finish:
//  freeReplyObject(reply);
//  redisFree(c);

    return rv;
}

static void rcache_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(rcache_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char* rcache_set_var_port(cmd_parms* cmd, void* dummy, const char* arg)
{
    rcache_info* info = ap_get_module_config(cmd->server->module_config, &rcache_module);
    info->port = atoi( apr_pstrdup(cmd->pool, arg) );
    return NULL;
}

static const char* rcache_set_var_hostname(cmd_parms* cmd, void* dummy, const char* arg)
{
    rcache_info* info = ap_get_module_config(cmd->server->module_config, &rcache_module);
    info->hostname = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const command_rec rcache_cmds[] = {
    AP_INIT_TAKE1("RedisHostname", rcache_set_var_hostname, NULL, OR_ALL, "Redis Server Hostname"),
    AP_INIT_TAKE1("RedisPort",     rcache_set_var_port,     NULL, OR_ALL, "Redis Server Port"),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA rcache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_config,
    NULL,
    rcache_cmds,
    rcache_register_hooks
};

