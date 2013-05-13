/*
 * this is an Apache module that applies the Content Security Policy script-nonce directive.
 * gila vinas, Jillian Munson, Cody Moore 
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
static const char s_NonceName[]="NonceFilter";
module AP_MODULE_DECLARE_DATA nonce_filter_module;

//This is where we store directive-populated values
//e.g. nonce, key
typedef struct{
int isEnabled;
const char *key;
const char *nonce;
} NonceConfig;
/*
Not *totally* necessary, but this is useful for configuring parameters before our conf
file is read
*/
static void *NonceFilterConfig(apr_pool_t *p, server_rec *s)
{
	NonceConfig *hConfig=apr_pcalloc(p, sizeof *hConfig);
	hConfig->isEnabled=0;
	return hConfig;
}

/*
	Inserts our output file into the list of filters to be called by mod_filter
*/
static void NonceFilterInsertFilter(request_rec *r)
{
	NonceConfig *hConfig=ap_get_module_config(r->server->module_config, &nonce_filter_module);
	if(!hConfig->isEnabled)
		return;

	ap_add_output_filter(s_NonceName, NULL, r,r->connection);
}

typedef struct {
   // apr_pool_t *tpool;
	//to make nonce consistent across brigades
	const char *nonce;
} csp_policy_mod_ctx;

/*
This will be where our filter logic goes
*/
static apr_status_t NonceFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
	/*
		So right now this is the boilerplate for iterating through the
		bucket brigade.  We need to add a bucket to insert at the head of the
		brigade to be our header, and then iterate through the buckets in the brigade
		to find "<script>" tags.
	*/
	csp_policy_mod_ctx *ctx = f->ctx;
    
	//Grab the request object from the filter context	
	request_rec *r = f->r;
	//From the request object, grab connection details
	//Useful for access to the existing pool to allocate mem for buckets
	conn_rec *c = r->connection;
	//The bucket we will use to catch the input in each bucket
	apr_bucket *hbktIn;
	//The object we will eventually return and pass back to mod_filter
	apr_bucket_brigade *pbbOut;
	NonceConfig *hConfig=ap_get_module_config(r->server->module_config, &nonce_filter_module);

	//Let's allocate some space for our output bucket brigade
	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);

	const char *k = hConfig->key;


	if (!ctx) {

  		 f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));

		//generate nonce for this connection
		ctx->nonce=nonce_rand_gen();
		//add CSP headers
		apr_table_t *headers= r->headers_out;
		//char *val= (char*)malloc((sizeof("script-nonce ") + sizeof(nonce)) * sizeof('a'));
		//char *script= "script-nonce ";
		//sprintf(val, "%s%s", "script-nonce ", nonce);
		//currently this is the only one being supported
		apr_table_setn(headers, "X-WebKit-CSP", apr_pstrcat(c->pool, "script-nonce ", ctx->nonce, NULL));
		//might be useful with future support for script-nonce
		apr_table_setn(headers, "Content-Security-Policy", apr_pstrcat(c->pool, "script-nonce ", ctx->nonce, NULL));
		apr_table_setn(headers, "X-Content-Security-Policy", apr_pstrcat(c->pool, "script-nonce ", ctx->nonce, NULL));
		apr_table_unset(f->r->headers_out, "Content-Length");
		//free(val);
		 //First, generate nonce
}
	const char *nonce=ctx->nonce;
	//Assign the current bucket to hbktIn (this will always be the case unless there are
	//no more buckets bc we remove them from the incoming bucket brigade each iteration)
	   for (hbktIn = APR_BRIGADE_FIRST(pbbIn);
         hbktIn != APR_BRIGADE_SENTINEL(pbbIn);
         hbktIn = APR_BUCKET_NEXT(hbktIn))
    {
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;
        apr_bucket *pbktOut;

        //Is this the last bucket, 
        if(APR_BUCKET_IS_EOS(hbktIn))
            {
            apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
            continue;
            }

        /* read */
        apr_bucket_read(hbktIn,&data,&len,APR_BLOCK_READ);

        //Right now this filters output and converts all characters to upper case.
		  int worst = (strlen(nonce))/ strlen(k); worst++;
        apr_size_t new_bucket_size = len;//
        buf = apr_bucket_alloc(len * worst, c->bucket_alloc);
        apr_size_t new_index = 0;
        apr_size_t i = 0;
        for(i; i < len; i++)
        {
            if(strncmp(&data[i], k, 1) == 0)
                {
                    int isKey = 0;
                    int j = 0;
                    for (j; j < strlen(k); j++)
                    {
                        if(strncmp(&data[i + j], &k[j], 1) != 0)
                            isKey = 1;
                    }
                    if(isKey == 0)
                    {
                        int n = 0;
								new_bucket_size+= (apr_size_t)(strlen(nonce)) - (apr_size_t)strlen(k);
                        i = i + strlen(k);
                        for(n; n < strlen(nonce); n++)
                        {
                            buf[new_index] = nonce[n];
                            new_index++;
                        }
                    }
            }
            buf[new_index] = data[i];
            new_index++;
        }
        pbktOut = apr_bucket_heap_create(buf, new_bucket_size, apr_bucket_free, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
        }
       	//So I don't think we can do this directly 
        //Possibly need to create a bucket and insert at the head?  Not sure
       //apr_table_set(r->headers_out, "Script-Nonce", nonce);
    apr_brigade_cleanup(pbbIn);
    ap_pass_brigade(f->next,pbbOut);
	 return APR_SUCCESS;
    }
/*
Function to grab the script nonce key from the .conf file for mod_nonce_filter
and put it in our NonceFilterConfig struct so we have access to it in our output function
*/
static const char *NonceFilterSetKey(cmd_parms *cmd, void *cfg, char *arg)
    {
    NonceConfig *hConfig=ap_get_module_config(cmd->server->module_config,&nonce_filter_module);
    hConfig->key=arg;
    return NULL;
    }

/*
Apache boilerplate -- reads in the value of "NonceKey" directive
*/
static const command_rec NonceFilterCmds[] =
    {
    AP_INIT_TAKE1("NonceKey", NonceFilterSetKey, NULL, OR_FILEINFO,"Directive to set script attribute nonce key"),
    { NULL }
    };
/*
Registers our input & output functions wth mod_filter, which actually calls our code.
*/ 
static void NonceRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(NonceFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_NonceName,NonceFilterOutFilter,NULL,AP_FTYPE_RESOURCE);
    }

module AP_MODULE_DECLARE_DATA nonce_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NonceFilterConfig,
    NULL,
    NonceFilterCmds,
    NonceRegisterHooks
};
