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

//This is how we tell the server the name of our filter
static const char s_szHelloFilterName[]="HelloFilter";
module AP_MODULE_DECLARE_DATA hello_filter_module;

//This is where we store directive-populated values
//e.g. nonceKey
typedef struct{
int isEnabled;
const char *nonce
} HelloConfig;

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

/*
This will be where our filter logic goes
*/
static apr_status_t HelloFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
	/*
		So right now this is the boilerplate for iterating through the
		bucket brigade.  We need to add a bucket to insert at the head of the
		brigade to be our header, and then iterate through the buckets in the brigade
		to find "<script>" tags.
	*/

	//Grab the request object from the filter context	
	request_rec *r = f->r;
	//From the request object, grab connection details
	//Useful for access to the existing pool to allocate mem for buckets
	conn_rec *c = r->connection;
	//The bucket we will use to catch the input in each bucket
	apr_bucket *hbktIn;
	//The object we will eventually return and pass back to mod_filter
	apr_bucket_brigade *pbbOut;

	//Let's allocate some space for our output bucket brigade
	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);

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
        if(APR_BUCKET_IS_EOS(pbktIn))
            {
            apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
            continue;
            }

        /* read */
        apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

        /* write:
        This is where we need to add our logic.
        1. Find script nonce key in file
        2. Replace with base 64 encoded hash digest of our nonce
        3. Keep track of how much we increase the size of the file. 
        We shouldn't hardcode the length of the key, but we may have to*/
        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for(n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);

        pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
        }
       	//So I don't think we can do this directly 
        //Possibly need to create a bucket and insert at the head?  Not sure
       //apr_table_set(r->headers_out, "Script-Nonce", nonce);
    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next,pbbOut);
    }
/*
Function to grab the script nonce key from the .conf file for mod_hello_filter
and put it in our HelloFilterConfig struct so we have access to it in our output function
*/
static const char *HelloFilterSetKey(cmd_parms *cmd, void *dummy, char *arg)
    {
    HelloFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,
                                                   &hello_filter_module);
    pConfig->nonce=arg;

    return NULL;
    }

/*
Apache boilerplate -- reads in the value of "NonceKey" directive
*/
static const command_rec HelloFilterCmds[] =
    {
    AP_INIT_TAKE1("NonceKey", HelloFilterSetKey, NULL, RSRC_CONF,
                 "Directive to set script attribute nonce key"),
    { NULL }
    };
/*
Registers our input & output functions wth mod_filter, which actually calls our code.
*/ 
static void HelloRegisterHooks(apr_pool_t *p)
    {
    ap_hook_insert_filter(HelloFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szHelloFilterName,HelloFilterOutFilter,NULL,
                              AP_FTYPE_RESOURCE);
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
