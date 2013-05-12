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
const char *nonce;
} HelloConfig;

apr_size_t new_bucket_size=0;

/*
Not *totally* necessary, but this is useful for configuring parameters before our conf
file is read
*/

static char *replace_nonce(const char *oldString, const char *key, const char *nonce, int key_length)
{
    char *index;
    char newBuff[4096];
    apr_size_t n = 0;
    apr_size_t size_newstring = 0;


    for(index=oldString; *index; ++index)
    {
        const char a = *index;
        const char b = *key;
        if(apr_strnatcmp(&a, &b)==0)
        {
            apr_size_t j = 0;
            apr_size_t isNonceKey = 0;
            const char temp_index = index;
            const char temp_key = key;
            for (j; j < key_length && isNonceKey == 0; j++)
            {
                const char temp_char = index + j;
                const char temp_key_char = key + j;   
                if(apr_strnatcmp(&temp_char, &temp_key_char)!= 0)
                {
                    isNonceKey = 1;
                    break;
                };
            }
            if(isNonceKey==0)
            {
                char *temp = nonce;
                index=index + (key_length);
                apr_size_t k = 1;
                for(temp=nonce; *temp; ++temp)
                {
                    newBuff[n+k] = nonce[k];
                    size_newstring++;
                    k++;
                }
                n = n + (k + 1);
            }
        }
        newBuff[n] = *index;
        size_newstring++;
        n++;
    }
    newBuff[n + 1] = '\0';
    size_newstring++;
    char return_buff[size_newstring];
    for(n = 0; n < size_newstring; n++)
        return_buff[n] = newBuff[n];
    new_bucket_size = size_newstring;
    return return_buff;
}

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
	
  //First, generate nonce
  // Also generate unique nonce in struct
  const char *nonce=nonce_rand_gen();
    
	//Grab the request object from the filter context	
	request_rec *r = f->r;
	//From the request object, grab connection details
	//Useful for access to the existing pool to allocate mem for buckets
	conn_rec *c = r->connection;
	//The bucket we will use to catch the input in each bucket
	apr_bucket *hbktIn;
	//The object we will eventually return and pass back to mod_filter
	apr_bucket_brigade *pbbOut;
	HelloConfig *hConfig=ap_get_module_config(r->server->module_config, &hello_filter_module);
	
	//Let's allocate some space for our output bucket brigade
	pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
	
	// MOVED TO STRUCT: Assign variable to use for nonce_gen
/*	char *nonce;*/
/*	nonce = nonce_rand_gen();*/
/*	printf(nonce);*/
/*	free(nonce);*/
	const char *k = hConfig->key;
    char *index;
    for (index=k; *index; ++index)
        ;
    int key_length = index-k;
    for (index=nonce; *index; ++index)
        ;
    int nonce_length = index-nonce;

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
        buf = apr_bucket_alloc(len + nonce_length, c->bucket_alloc);
        buf = replace_nonce(data, k, nonce, key_length);

        pbktOut = apr_bucket_heap_create(buf, new_bucket_size, apr_bucket_free, c->bucket_alloc);
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
