// Flugegeheimen upstream module
// (c) Alexandr Chernakov, 2015

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define bool int
#define true 1
#define false 0

#define FLUG_UPSTREAM_ADDR "127.0.0.1"
#define FLUG_UPSTREAM_PORT "2345"
#define FLUG_UPSTREAM_LOG "nginx/logs/flug_upstream.log"

static time_t flug_log_timestamp (FILE * log) {
	time_t t;
	time(&t);
	fprintf(log, "%s: ", ctime(&t));
	return t;
}

static void flug_log_cstr (const char * str) {
	FILE * log = fopen(FLUG_UPSTREAM_LOG, "a");
	if (!log) {
		return;
	}

	flug_log_timestamp(log);
	fprintf (log, "%s\n",  str);

	fclose(log);

}

/*static void flug_log_nstr (ngx_str_t str) {
	FILE * log = fopen(FLUG_UPSTREAM_LOG, "a");
	if (!log) {
		return;
	}

	flug_log_timestamp(log);
	fwrite(str.data, sizeof(u_char), str.len, log);
	fprintf (log, "\n");

	fclose(log);
}*/

typedef struct {
	ngx_http_upstream_conf_t upstream;
	ngx_str_t addr;
	ngx_str_t port;
} flug_upstream_conf_t;


//Module context struct
typedef struct flug_module_context_s {
} flug_module_context_t;


void * flug_create_loc_conf (ngx_conf_t * cf);

//Module context setup
static ngx_http_module_t flug_module_ctx = {
	NULL, /* preconfiguration */
	NULL, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	//NULL, /* create location configuration */
	flug_create_loc_conf,

	NULL /* merge location configuration */
};



//Configuration commands setup

static char * flug_config_setup (ngx_conf_t *cf, ngx_command_t *cmd, void* conf);
static ngx_command_t flug_module_commands[] = {
	{
		ngx_string("flug_upstream"),
		NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
		flug_config_setup,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL,
	},

	ngx_null_command
};

//Main module struct
ngx_module_t ngx_http_flug_upstream_module = {
	NGX_MODULE_V1,
	&flug_module_ctx,
	flug_module_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

static ngx_http_module_t * flug_get_context (ngx_http_request_t * r) {
	flug_log_cstr ("flug_get_context");
	ngx_http_module_t * ctx = ngx_http_get_module_ctx (r, ngx_http_flug_upstream_module);
	if (ctx == NULL) {
		ctx = ngx_palloc(r->pool, sizeof(ngx_http_module_t));
	}

	if (ctx == NULL) {
		return NULL;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_flug_upstream_module);

	return ctx;
}

//Sockaddr/socklen structs resolving

/*static ngx_int_t flug_resolve_upstream (ngx_http_upstream_resolved_t * resolved) {
	int ret;
	int sfd = -1;
	bool connected = false;
	struct addrinfo hints, *results;
	struct addrinfo *rp;

	flug_log_cstr ("Resolving address");

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    
	hints.ai_socktype = SOCK_STREAM; 

	ret = getaddrinfo("127.0.0.1", "2345", &hints, &results);
	if (ret) {
		return -1;
	}
	for (rp = results; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			close(sfd);

			resolved->sockaddr = rp->ai_addr;
			resolved->socklen = rp->ai_addrlen;
			resolved->naddrs = 1;

			connected = true;
			break;                  // Success 
		}
	}

	if (!connected) {
		return NGX_ERROR;
	} 

	return NGX_OK;
}*/



/*static ngx_buf_t * flug_wrap_request (ngx_str_t req) {
	int32_t size = req.len;

	return NULL;
}*/

static ngx_int_t flug_upstream_process_header(ngx_http_request_t * r) {
	flug_log_cstr("flug_upstream_process_header");
	return NGX_ERROR;
}
static void flug_upstream_finalize_request(ngx_http_request_t * r, ngx_int_t rc) {
	flug_log_cstr("flug_upstream_finalize_request");
}
static ngx_int_t flug_upstream_create_request(ngx_http_request_t * r) {
	//ngx_str_t dummyRequest = ngx_string("{\"subsystem\":\"asdfasd\"}");
	flug_log_cstr ("flug_upstream_create_request");
	return NGX_OK;
}

//Setup the connection details like as sockaddr/socklen structs
static ngx_int_t flug_setup_upstream (ngx_http_request_t * r, ngx_http_module_t * ctx) {

	flug_log_cstr ("flug_setup_upstream");
	
	if (ngx_http_upstream_create(r) != NGX_OK) {
		flug_log_cstr("Failed to create upstream");
		return NGX_ERROR;
	}

	/*ngx_http_upstream_t * u = ngx_palloc(r->pool, sizeof(ngx_http_upstream_t));
	if (!u) {
		return NGX_ERROR;
	}*/

	flug_upstream_conf_t *mycf = (flug_upstream_conf_t*)
			ngx_http_get_module_loc_conf(r,ngx_http_flug_upstream_module);

	if (!mycf) {
		flug_log_cstr("Failed to ngx_http_get_module_loc_conf");
		return NGX_ERROR;
	}

	ngx_http_upstream_t * u = r->upstream;
	if (!r->upstream) {
		flug_log_cstr("r->upstream is null");
	}
	u->conf = &mycf->upstream;
	u->buffering = mycf->upstream.buffering;
	u->resolved = (ngx_http_upstream_resolved_t *) 
			ngx_palloc(r->pool,sizeof(ngx_http_upstream_resolved_t));

	u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
	if (!u->resolved) {
		return NGX_ERROR;
	}

	static struct sockaddr_in backendSockAddr;
	struct hostent *pHost = gethostbyname((char*) "www.google.com");


	if(pHost == NULL){
		ngx_log_error(NGX_LOG_DEBUG,r->connection->log,0,"gethostbyname error:%s",strerror(errno));
		return NGX_ERROR;
	}
	//Access to the upstream server porflug_request_handlert
	backendSockAddr.sin_family = AF_INET;
	backendSockAddr.sin_port = htons((in_port_t)80);
	char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
	backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
	//myctx->backendServer.data = (u_char * )pDmsIP;
	//myctx->backendServer.len = strlen(pDmsIP);


	//Set the address to resolved members
	u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
	u->resolved->socklen = sizeof(struct sockaddr_in );
	u->resolved->naddrs = 1;

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;
	
	u->create_request = flug_upstream_create_request;
	u->process_header = flug_upstream_process_header;
	u->finalize_request = flug_upstream_finalize_request;

	r->upstream = u;

	return NGX_OK;
}

//Main request handler
static ngx_int_t flug_request_handler (ngx_http_request_t * r) {

	flug_log_cstr("flug_request_handler");
	ngx_int_t rc;
	ngx_http_module_t * ctx;

	flug_log_cstr("Try get context");
	ctx = flug_get_context(r);
	if (!ctx) {
		flug_log_cstr("Get context failed");
		return NGX_ERROR;
	}

	flug_log_cstr("Setup upstream");
	if (flug_setup_upstream(r, ctx) != NGX_OK) {
		flug_log_cstr("Setup upstream failed");
		return NGX_ERROR;
	}

	
	//r->main->count++;  //dafaq iz dat

	flug_log_cstr ("request_body() handled with upstream_init");	
	rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		flug_log_cstr("Special response");
		return rc;
	}

	flug_log_cstr("Returning NGX_DONE");
	return NGX_DONE;
}


//Create location configuration
void * flug_create_loc_conf (ngx_conf_t * cf) {

	flug_upstream_conf_t * loc_conf = ngx_palloc (cf->pool, sizeof (flug_upstream_conf_t));

	if (!loc_conf) {
		flug_log_cstr ("Failed to allocate loc_conf struct");
		return NULL;
	}

	loc_conf->upstream.connect_timeout = 60000;
	loc_conf->upstream.send_timeout = 60000;
	loc_conf->upstream.read_timeout = 60000;

	loc_conf->upstream.store_access = 0600;
	loc_conf->upstream.buffering = 0;
	loc_conf->upstream.bufs.num = 8;

	loc_conf->upstream.bufs.size = ngx_pagesize;
	loc_conf->upstream.buffer_size = ngx_pagesize;
	loc_conf->upstream.busy_buffers_size = 2 * ngx_pagesize;
	loc_conf->upstream.temp_file_write_size = 2 * ngx_pagesize;
	loc_conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
	loc_conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
	loc_conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
	
	return loc_conf;
}

//Handle configuration file command
static char * flug_config_setup (ngx_conf_t *cf, ngx_command_t *cmd, void* conf) {
	
	flug_log_cstr("Starting flug_upstream module init");

	ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

	/* Install the hello world handler. */
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = flug_request_handler;
	flug_log_cstr("Finished flug_upstream module init");

	return NGX_CONF_OK;


}


