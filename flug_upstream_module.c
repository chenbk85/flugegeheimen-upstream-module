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
#define FLUG_UPSTREAM_MIME "application/json"

#define FLUG_DEBUG_LOG 1

static time_t flug_log_timestamp (FILE * log) {
	time_t t;
	char data[100], *ptr;
	time(&t);
	strcpy(data, ctime(&t));
	for(ptr = data; ((*ptr = (*ptr == '\n')?' ':*ptr),(*ptr)); ptr++);
	fprintf(log, "%s: ", data);
	return t;
}

static void flug_log_cstr (const char * str) {
	if (!FLUG_UPSTREAM_LOG) {
		return;
	}
	FILE * log = fopen(FLUG_UPSTREAM_LOG, "a");
	if (!log) {
		return;
	}

	flug_log_timestamp(log);
	fprintf (log, "%s\n",  str);

	fclose(log);

}

static void flug_log_nstr (ngx_str_t str) {
	if (!FLUG_UPSTREAM_LOG) {
		return;
	}
	FILE * log = fopen(FLUG_UPSTREAM_LOG, "a");
	if (!log) {
		return;
	}

	flug_log_timestamp(log);
	fwrite(str.data, sizeof(u_char), str.len, log);
	fprintf (log, "\n");

	fclose(log);
}

static void flug_log_numeric_parameter (const char * name, uint32_t number) {

	if (!FLUG_UPSTREAM_LOG) {
		return;
	}
	FILE * log = fopen(FLUG_UPSTREAM_LOG, "a");
	if (!log) {
		return;
	}

	flug_log_timestamp(log);
	fprintf (log, "%s: %u\n", name, number);

	fclose(log);

}

typedef struct {
	ngx_http_upstream_conf_t upstream;
	ngx_str_t addr;
	ngx_str_t port;
} flug_upstream_conf_t;


//Module context struct
typedef struct flug_request_context_s {
	uint32_t size;
	uint32_t sent;
	bool initDone;
} flug_request_context_t;

typedef struct flug_filter_context_s {
	ngx_http_request_t * r;
	ngx_http_upstream_t * u;
} flug_filter_context_t;

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

static ngx_int_t flug_resolve_upstream (ngx_http_upstream_resolved_t * resolved) {
	int ret;
	//int sfd = -1;
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
		/*sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			close(sfd);

			resolved->sockaddr = rp->ai_addr;
			resolved->socklen = rp->ai_addrlen;
			resolved->naddrs = 1;

			connected = true;
			break;                  // Success 
		}*/
		resolved->sockaddr = rp->ai_addr;
		resolved->socklen = rp->ai_addrlen;
		resolved->naddrs = 1;

		connected = true;
		break;                  // Success 

	}

	if (!connected) {
		return NGX_ERROR;
	} 

	return NGX_OK;
}



typedef struct {
	size_t rest;
	ngx_http_request_t *request;
	ngx_http_upstream_t *upstream;
} flug_upstream_filter_ctx;


flug_upstream_filter_ctx * flug_create_filter_context (ngx_http_request_t * r) {
	if (!r || !r->upstream) {
		return NULL;
	}

	flug_upstream_filter_ctx * ctx = 
			ngx_pcalloc(r->pool, sizeof(flug_upstream_filter_ctx));
	if (!ctx) {
		return NULL;
	}

	ctx->request = r;
	ctx->upstream = r->upstream;

	return ctx;
}


static ngx_int_t flug_upstream_filter_init(void *data) {
	flug_log_cstr("flug_upstream_input_filter_init");
	if (!data) {
		return NGX_ERROR;
	}

	//get context from data pointer
	flug_upstream_filter_ctx * ctx = data;
	//setup content length 
	ngx_http_upstream_t * u = ctx->upstream;

	
	u->length = u->headers_in.content_length_n;
	return NGX_OK;
}


static ngx_int_t flug_upstream_filter(void *data, ssize_t bytes) {
	u_char               *last;
	ngx_buf_t            *b;
	ngx_chain_t          *cl, **ll;

	flug_log_cstr("flug_upstream_input_filter");
	if (!data) {
		return NGX_ERROR;
	}

	//get context from data pointer
	flug_upstream_filter_ctx * ctx = data;
	//setup content length 
	ngx_http_upstream_t * u = ctx->upstream;
	b = &u->buffer;


    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }
	
    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

	/*cl->buf->pos = b->last;
	b->last += bytes;
	cl->buf->last = b->last;
	cl->buf->tag = u->output.tag;*/

	u->length -= bytes;
	if (u->length == 0) {
		u->keepalive = 1;
	}
	return NGX_OK;
}

static ngx_int_t flug_chain_to_str (ngx_http_request_t * r,
								ngx_chain_t * chain,
								ngx_str_t * str) {
	ngx_chain_t * ptr;
	ngx_int_t size = 0, counter = 0;
	for (ptr = chain; ptr; ptr = ptr->next)
		size += ptr->buf->last - ptr->buf->pos;

	str->data = ngx_pcalloc(r->pool, size);
	if (!str->data) {
		return -1;
	}

	for (ptr = chain; ptr; ptr = ptr->next) {
		memcpy(str->data + counter, ptr->buf->pos, ptr->buf->last - ptr->buf->pos);
		counter += ptr->buf->last - ptr->buf->pos;
	}
	str->len = size;

	return 0;
}


static ngx_int_t flug_upstream_process_header(ngx_http_request_t * r) {
	ngx_http_upstream_t       *u;
	uint32_t respSize, rawSize;

	u = r->upstream;
	flug_log_cstr("flug_upstream_process_header");
	rawSize = u->buffer.last - u->buffer.pos;
	flug_log_numeric_parameter("Size of data transmited by upstream", rawSize);
	if (rawSize < sizeof(uint32_t)) {
		return NGX_ERROR;
	}
	flug_log_numeric_parameter("Size of data by start/end pair", 
			(uint32_t)(u->buffer.end - u->buffer.start));


	flug_request_context_t * ctx = 
			ngx_http_get_module_ctx(r, ngx_http_flug_upstream_module);

	if (!ctx) {
		flug_log_cstr("Failed to get context");
		return NGX_ERROR;
	}

	ngx_memcpy((u_char*)&respSize, u->buffer.pos, sizeof(uint32_t));

	r->headers_out.content_type.len = sizeof(FLUG_UPSTREAM_MIME) - 1;
	r->headers_out.content_type.data = (u_char *) FLUG_UPSTREAM_MIME;
	u->buffer.pos += sizeof(uint32_t);

	u->state->status = NGX_HTTP_OK;
	u->headers_in.status_n = NGX_HTTP_OK;

	u->headers_in.content_length_n = (off_t)respSize;

	return NGX_OK;

}

static void flug_upstream_finalize_request(ngx_http_request_t * r, ngx_int_t rc) {
	flug_log_cstr("flug_upstream_finalize_request");
}

static flug_request_context_t * flug_upstream_new_request_ctx (ngx_http_request_t * r) {
	flug_log_cstr("Creating new request context");

	
	flug_request_context_t * reqCtx = ngx_pcalloc(r->pool, sizeof (flug_request_context_t));
	if (!reqCtx) {
		return NULL;
	}

	reqCtx->size = 0;
	reqCtx->sent = 0;
	reqCtx->initDone = 0;

	ngx_http_set_ctx(r, reqCtx, ngx_http_flug_upstream_module);
	return reqCtx;
}

static ngx_int_t flug_upstream_create_request(ngx_http_request_t * r) {
	ngx_int_t err;
	ngx_str_t postData = {0, NULL};
	ngx_buf_t * upstream_buf;
	uint32_t upstream_len;
	
	flug_log_cstr ("flug_upstream_create_request");

	flug_request_context_t * reqCtx = flug_upstream_new_request_ctx(r);
	if (!reqCtx) {
		flug_log_cstr("Failed to create rewuest context");
		return NGX_ERROR;
	}

	err = flug_chain_to_str (r, r->request_body->bufs, &postData);
	if (err) {
		flug_log_cstr ("Failed to get POST body from chain");
		return NGX_ERROR;
	}


	flug_log_nstr (postData);

	//create request to flugegeheimen server out of postData
	
	r->upstream->request_bufs = ngx_alloc_chain_link (r->pool);
	if (r->upstream->request_bufs == NULL) {
		flug_log_cstr("Failed to allocate chain link to store upstream request");
		return NGX_ERROR;
	}

	upstream_len = postData.len;
	upstream_buf = ngx_create_temp_buf (r->pool, postData.len + sizeof (uint32_t));
	ngx_memcpy(upstream_buf->pos + sizeof(uint32_t), postData.data, postData.len);
	ngx_memcpy(upstream_buf->pos, (u_char*)&upstream_len, sizeof(uint32_t));
	upstream_buf->last = upstream_buf->pos + upstream_len + sizeof(uint32_t);

	

	r->upstream->request_bufs->buf = upstream_buf;
	r->upstream->request_bufs->next = NULL;

	r->upstream->request_sent = 0;
	r->upstream->header_sent = 0;

	r->header_hash = 0;

	return NGX_OK;
}
void flug_upstream_abort_request (ngx_http_request_t * r) {
	flug_log_cstr("ERROR! flug_upstream_abort_request");
}

ngx_int_t flug_upstream_reinit_request () {
	flug_log_cstr("ERROR! flug_reinit_abort_request");
	return NGX_ERROR;
}


//Setup the connection details like as sockaddr/socklen structs
static ngx_int_t flug_setup_upstream (ngx_http_request_t * r, ngx_http_module_t * ctx) {

	flug_log_cstr ("flug_setup_upstream");

	if (ngx_http_upstream_create(r) != NGX_OK) {
		flug_log_cstr("Failed to create upstream");
		return NGX_ERROR;
	}

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
	//u->keepalive = 0;
	u->buffering = mycf->upstream.buffering;

	u->resolved = ngx_palloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
	if (!u->resolved) {
		return NGX_ERROR;
	}
	u->resolved->ctx = NULL;


	if (flug_resolve_upstream(u->resolved) != NGX_OK) {
		flug_log_cstr("Failed to resolve route to flugegeheimen server, bitch");
		return NGX_ERROR;
	}

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;

	u->create_request = flug_upstream_create_request;
	u->process_header = flug_upstream_process_header;
	u->finalize_request = flug_upstream_finalize_request;

	r->upstream = u;

	u->input_filter_init = flug_upstream_filter_init;
	u->input_filter = flug_upstream_filter;
	u->input_filter_ctx = flug_create_filter_context(r);
	u->keepalive = 1;
	//if (!u->input_filter_ctx) {
	//	return NGX_ERROR;
	//}

	return NGX_OK;
}

//Main request handler
static ngx_int_t flug_request_handler (ngx_http_request_t * r) {
	flug_log_cstr("\n\nflug_request_handler");
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

	flug_log_cstr("Returning NGX_OK");
	return NGX_OK;
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


