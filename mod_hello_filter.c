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
