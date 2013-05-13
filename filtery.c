    /*A hello world module to test
*adding/modifying content using 
*existing mod_filter 

To-do's:
- Implement some modification of data in the bucket brigade iterator 
to test output to make sure it works.
- Test adding a header to r->headers_out table with and without creating a bucket
- Add logic to generate nonce, hash, and base64 encode.
- Continue looking at mod_txt.c to figure out best way to search-and-replace
text in the file (e.g. combine all buckets into one buffer and search?  HTML parsing library?
Is there html parsing functionality in apache already?) -- 
- Also mod_substitue?  
- 
*/

#include <httpd.h>
#include <http_config.h>
#include <apr_buckets.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_strmatch.h>
#include <util_filter.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "nonce_gen/nonce_rand.h"

//This is how we tell the server the name of our filter
static const char s_szHelloFilterName[]="HelloFilter";
module AP_MODULE_DECLARE_DATA hello_filter_module;

//This is where we store directive-populated values
//e.g. nonce, key
typedef struct{
int isEnabled;
const char *key;
//const char *nonce;
} HelloConfig;

//char newBuff[4096];
/*
Not *totally* necessary, but this is useful for configuring parameters before our conf
file is read
*/
static void *HelloFilterConfig(apr_pool_t *p, server_rec *s)
{
	HelloConfig *hConfig=apr_pcalloc(p, sizeof *hConfig);
	hConfig->isEnabled=0;
	return hConfig;
}

/*
	Inserts our output file into the list of filters to be called by mod_filter
*/
static void HelloFilterInsertFilter(request_rec *r)
{
	HelloConfig *hConfig=ap_get_module_config(r->server->module_config, &hello_filter_module);
	if(!hConfig->isEnabled)
		return;

	ap_add_output_filter(s_szHelloFilterName, NULL, r,r->connection);
}

typedef struct {
    //apr_bucket_brigade *linebb;
    //apr_bucket_brigade *linesbb;
    //apr_bucket_brigade *passbb;
    //apr_bucket_brigade *pattbb;
    apr_pool_t *tpool;
	const char *nonce;
} csp_policy_mod_ctx;

/*
This will be where our filter logic goes
http://svn.apache.org/repos/asf/httpd/sandbox/amsterdam/d/modules/filters/mod_substitute.c
*/
static apr_status_t HelloFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    //Grab the request object from the filter context	
    request_rec *r = f->r;
    //From the request object, grab connection details
    //Useful for access to the existing pool to allocate mem for buckets
    conn_rec *c = r->connection;
	HelloConfig *hConfig=ap_get_module_config(r->server->module_config, &hello_filter_module);
	const char *k = hConfig->key;
	apr_bucket *b;
	apr_bucket_brigade *tmpbb= apr_brigade_create(f->r->pool, f->c->bucket_alloc); 

   

    csp_policy_mod_ctx *ctx = f->ctx;
    
   //first brigade for this request
    if (!ctx) {
		
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));

		//generate nonce for this connection
		ctx->nonce=nonce_rand_gen();
		
		//add CSP headers
		apr_table_t *headers= r->headers_out;
		char *val = (char*) malloc((strlen("script-nonce ") + strlen(ctx->nonce) + 1) * sizeof('a') );
		sprintf(val, "%s%s", "script-nonce ", ctx->nonce);
		//currently this is the only one being supported
		apr_table_setn(headers, "X-WebKit-CSP", val);
		//might be useful with future support for script-nonce
		apr_table_setn(headers, "Content-Security-Policy", val);
		apr_table_setn(headers, "X-Content-Security-Policy", val);
		free(val);
		
        //ctx->linebb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        //ctx->linesbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        //ctx->pattbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
        /*
         * Everything to be passed to the next filter goes in
         * here, our pass brigade.
         */
        //ctx->passbb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

        /* Create our temporary pool only once */
        apr_pool_create(&(ctx->tpool), f->r->pool);
        apr_table_unset(f->r->headers_out, "Content-Length");
    }

    /*
     * Shortcircuit processing
     */
    if (APR_BRIGADE_EMPTY(bb))
        return APR_SUCCESS;
	
	const char *data;
	int isKey = 0;
	apr_size_t len;
	char *s;
	apr_pool_t *tmp_pool;
	apr_pool_create(&tmp_pool, ctx->tpool);
	
    while ((b = APR_BRIGADE_FIRST(bb)) && (b != APR_BRIGADE_SENTINEL(bb))) {
        if(apr_bucket_read(b, &data, &len, APR_BLOCK_READ)==APR_SUCCESS){
		char *buf = apr_bucket_alloc(len, c->bucket_alloc);
		int n;//index into data
		int r;
		
		for(n=0 ; n < len ; ++n)
            buf[n] = apr_tolower(data[n]);
		
		for (n=0; n < len; n++){
			s= apr_pstrmemdup(tmp_pool, buf +n, sizeof(k));
			r=apr_strnatcmp(s, k);
			if(r == 0 && n!=0){
				apr_bucket_split(b, n);
             	APR_BUCKET_REMOVE(b);
				APR_BRIGADE_INSERT_HEAD(tmpbb, b);
				apr_brigade_cleanup(b);
				ap_pass_brigade(f->next, tmpbb);
				apr_brigade_cleanup(tmpbb);
				apr_pool_clear(tmp_pool);
				return APR_SUCCESS;
			} else if (r == 0 && n==0){
				apr_bucket_split(b, sizeof(k));
				APR_BUCKET_REMOVE(b);
				apr_bucket *nb= apr_bucket_heap_create(ctx->nonce, (apr_size_t)sizeof(ctx->nonce), apr_bucket_free, f->r->connection->bucket_alloc);
				APR_BRIGADE_INSERT_HEAD(tmpbb, nb);
				apr_brigade_cleanup(b);
				ap_pass_brigade(f->next, tmpbb);
				apr_brigade_cleanup(tmpbb);
				apr_pool_clear(tmp_pool);
				return APR_SUCCESS;
			}
		apr_pool_clear(tmp_pool);
		apr_brigade_cleanup(tmpbb);
		return APR_SUCCESS;
		}
		}
		
		/*
		int i=0;
		char *buf = apr_bucket_alloc(len, c->bucket_alloc);
		int n;
		for(n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);
		if (apr_strnatcmp(buf, k)) i=1;
		
		apr_bucket_split(b, 5);*/
		/*
		APR_BUCKET_REMOVE(b);
		APR_BRIGADE_INSERT_HEAD(tmpbb, b);
		ap_pass_brigade(f->next, tmpbb);
		apr_brigade_cleanup(tmpbb);
		
		*/
	}
	return APR_SUCCESS;
}

/*
Function to grab the script nonce key from the .conf file for mod_hello_filter
and put it in our HelloFilterConfig struct so we have access to it in our output function
*/
static const char *HelloFilterSetKey(cmd_parms *cmd, void *cfg, char *arg)
    {
    HelloConfig *hConfig=ap_get_module_config(cmd->server->module_config,&hello_filter_module);
    hConfig->key=arg;
    return NULL;
    }

/*
Apache boilerplate -- reads in the value of "NonceKey" directive
*/
static const command_rec HelloFilterCmds[] =
    {
    AP_INIT_TAKE1("NonceKey", HelloFilterSetKey, NULL, OR_FILEINFO,"Directive to set script attribute nonce key"),
    { NULL }
    };
/*
Registers our input & output functions wth mod_filter, which actually calls our code.
*/ 
static void HelloRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(HelloFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szHelloFilterName,HelloFilterOutFilter,NULL,AP_FTYPE_RESOURCE);
    }

module AP_MODULE_DECLARE_DATA hello_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    HelloFilterConfig,
    NULL,
    HelloFilterCmds,
    HelloRegisterHooks
};
