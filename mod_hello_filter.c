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

typedef struct{
int isEnabled;
} HelloConfig;

static void *HelloFilterConfig(apr_pool_t *p, server_rec *s
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

static apr_status_t HelloFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	apr_bucket *hbktIn;
	apr_bucket_brigade *pbbOut;

	pbbOut=apr_brigade_create(r->)
}