/*A hello world module to test
*adding/modifying content using 
*existing mod_filter functionality
*/

#include <httpd.h>
#include <http_config.h>
#include <apr_buckets.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <util_filter.h>
#include <ctype.h>

static const char s_szHelloFilterName[]="HelloFilter";
module AP_MODULE_DECLARE_DATA hello_filter_module;

//This is where we store directive-populated values
//e.g. nonceKey
typedef struct{
int isEnabled;
const char *nonce
} HelloConfig;

static void *HelloFilterConfig(apr_pool_t *p, server_rec *s)
{
	HelloConfig *hConfig=apr_pcalloc(p, sizeof *hConfig);
	hConfig->isEnabled=0;
	return hConfig;
}

static void HelloFilterInsertFilter(request_rec *r)
{
	HelloConfig *hConfig=ap_get_module_config(r->server->module_config, &hello_filter_module);

	if(!hConfig->isEnabled)
		return;

	ap_add_output_filter(s_szHelloFilterName, NULL, r,r->connection);
}

/*This will be where our filter logic goes
Idea: From the request object, 
*/
static apr_status_t HelloFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	apr_bucket *hbktIn;
	apr_bucket_brigade *pbbOut;

	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
	   for (hbktIn = APR_BRIGADE_FIRST(pbbIn);
         hbktIn != APR_BRIGADE_SENTINEL(pbbIn);
         hbktIn = APR_BUCKET_NEXT(hbktIn))
    {
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;
        apr_bucket *pbktOut;

        if(APR_BUCKET_IS_EOS(pbktIn))
            {
            apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
            continue;
            }

        /* read */
        apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

        /* write */
        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for(n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);

        pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
        }
    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next,pbbOut);
    }

static const char *HelloFilterSetKey(cmd_parms *cmd, void *dummy, char *arg)
    {
    HelloFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,
                                                   &hello_filter_module);
    pConfig->nonce=arg;

    return NULL;
    }

static const command_rec HelloFilterCmds[] =
    {
    AP_INIT_TAKE1("NonceKey", HelloFilterSetKey, NULL, RSRC_CONF,
                 "Directive to set script attribute nonce key"),
    { NULL }
    };

static void CaseFilterRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(CaseFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szCaseFilterName,CaseFilterOutFilter,NULL,
                              AP_FTYPE_RESOURCE);
    }


module AP_MODULE_DECLARE_DATA case_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    HelloFilterConfig,
    NULL,
    HelloFilterCmds,
    CaseFilterRegisterHooks
};
