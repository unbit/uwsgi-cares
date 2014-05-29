#include <uwsgi.h>
#include <ares.h>
#include <arpa/nameser.h>

extern struct uwsgi_server uwsgi;

/*

	--cares-server = [strlist]
	--cares-timeout = <int>
	--cares-cache = <cache_name>
	--cares-cache-ttl = <cache_name>

	${dns[HTTP_HOST]}

	TODO
	${dns_txt[HTTP_HOST]}
	${dns_ptr[REMOTE_ADDR]}
*/

static struct uwsgi_cares {
	int initialized;
	int timeout;
	char *cache;
	int ttl;
} ucares;


static char *dns_get_a(char *, uint16_t, uint16_t *);

static void uwsgi_opt_dns_resolve(char *opt, char *value, void *foo) {
	char *equal = strchr(value, '=');
	if (!equal) {
		uwsgi_log("invalid cares-resolve syntax, must be placeholder=domain\n");
		exit(1);
	}
	uint16_t ip_len = 0;
	char *ip = dns_get_a(equal+1, strlen(equal+1), &ip_len);
	if (!ip) {
		uwsgi_log("[uwsgi-cares] unable to resolve name %s\n", equal+1);
		exit(1);
	}
	char *new_opt = uwsgi_concat2n(value, (equal-value)+1, ip, ip_len);
	uwsgi_opt_set_placeholder(opt, new_opt, (void *) 1);
}

struct uwsgi_option cares_options[] = {
	{"cares-cache", required_argument, 0, "cache every c-ares query in the specified uWSGI cache", uwsgi_opt_set_str, &ucares.cache, 0},
	{"cares-cache-ttl", required_argument, 0, "force the ttl when caching dns query results", uwsgi_opt_set_int, &ucares.ttl, 0},
	{"cares-resolve", required_argument, 0, "place the result of a dns query in the specified placeholder, sytax: placeholder=name (immediate option)", uwsgi_opt_dns_resolve, NULL, UWSGI_OPT_IMMEDIATE},
	UWSGI_END_OF_OPTIONS
};

struct uwsgi_cares_query {
	int cb_done;
	int ok;
	char *domain_name;
	uint16_t domain_name_len;
	struct uwsgi_buffer *ub;
};

void dns_a_cb(void *arg, int status, int timeouts, unsigned char *buf, int len) {
	struct uwsgi_cares_query *ucq = (struct uwsgi_cares_query *) arg;
	ucq->cb_done = 1;
	if (status != ARES_SUCCESS) return;

	struct ares_addrttl attl[30];
	int ttl = 30;

	int ret = ares_parse_a_reply(buf, len, NULL, attl, &ttl);
	if (ret != ARES_SUCCESS) return;
	if (!inet_ntop(AF_INET, &attl[0].ipaddr, ucq->ub->buf, ucq->ub->len)) {
               	uwsgi_error("[uwsgi-cares] inet_ntop()");
		return;
	}
	ucq->ub->pos = strlen(ucq->ub->buf);
	// cache the result ?
	if (ucares.cache) {
		if (ucares.ttl) ttl = ucares.ttl;
		uwsgi_cache_magic_set(ucq->domain_name, ucq->domain_name_len, ucq->ub->buf, ucq->ub->pos, ttl,
                                UWSGI_CACHE_FLAG_UPDATE, ucares.cache);
	}
	// ok
	ucq->ok = 1;
}

static char *dns_get_a(char *name, uint16_t name_len, uint16_t *ip_len) {
	char *result = NULL;
	ares_channel channel;
	ares_socket_t socks[ARES_GETSOCK_MAXNUM];

	struct uwsgi_cares_query ucq;
	memset(&ucq, 0, sizeof(struct uwsgi_cares_query));
	ucq.ub = uwsgi_buffer_new(INET_ADDRSTRLEN);

	char *port = memchr(name, ':', name_len);
	if (port) {
		ucq.domain_name = uwsgi_concat2n(name, port - name, "", 0);
		ucq.domain_name_len = port-name;
	}
	else {	
		ucq.domain_name = uwsgi_concat2n(name, name_len, "", 0);
		ucq.domain_name_len = name_len;
	}

	if (ucares.cache) {
		uint64_t valsize = 0;
		char *result = NULL;
        	char *value = uwsgi_cache_magic_get(ucq.domain_name, ucq.domain_name_len, &valsize, NULL, ucares.cache);
        	if (value) {
			free(ucq.domain_name);
			*ip_len = valsize;
			if (port) {	
				result = uwsgi_concat2n(value, valsize, port, name_len - (port-name));
				free(value);
				return result;
			}
			return value;
		}
	}

	int ret = ares_init(&channel);
	if (ret) {
		uwsgi_log("[uwsgi-cares] error: %s\n", ares_strerror(ret));
		return NULL;
	}

	ares_query(channel, ucq.domain_name, ns_c_in, ns_t_a, dns_a_cb, &ucq);
	
	for(;;) {
		int bitmask = ares_getsock(channel, socks, ARES_GETSOCK_MAXNUM);

		int i;
		for(i=0;i<ARES_GETSOCK_MAXNUM;i++) {

			if(ARES_GETSOCK_READABLE(bitmask, i)) {
				int ret = uwsgi.wait_read_hook(socks[i], ucares.timeout);
        			if (ret <= 0) goto end;
				ares_process_fd(channel, socks[i], ARES_SOCKET_BAD);
				if (ucq.cb_done) goto end;
				break;
			}

			if(ARES_GETSOCK_WRITABLE(bitmask, i)) {
				int ret = uwsgi.wait_write_hook(socks[i], ucares.timeout);
        			if (ret <= 0) goto end;
				ares_process_fd(channel, ARES_SOCKET_BAD, socks[i]);
				if (ucq.cb_done) goto end;
				break;
			}
		}
	}

end:
	free(ucq.domain_name);
	if (ucq.cb_done && ucq.ok) {
		if (port) {
			if (uwsgi_buffer_append(ucq.ub, port, name_len - (port-name))) goto end2;
		}
		*ip_len = ucq.ub->pos;
		result = ucq.ub->buf;
		// protect the buffer from being destroyed
		ucq.ub->buf = NULL;
	}
	
end2:
	uwsgi_buffer_destroy(ucq.ub);
	return result;
}

static char *uwsgi_route_var_dns_a(struct wsgi_request *wsgi_req, char *key, uint16_t keylen, uint16_t *vallen) {
        char *ret = NULL;
        uint16_t var_vallen = 0;
        char *var_value = uwsgi_get_var(wsgi_req, key, keylen, &var_vallen);
        if (var_value) {
                uint16_t ip_len = 0;
                ret = dns_get_a(var_value, var_vallen, &ip_len);
                if (ret) *vallen = ip_len;
        }
        return ret;
}

static void cares_register() {
	ucares.timeout = 10;
	int ret = ares_library_init(ARES_LIB_INIT_ALL);
	if (ret) {
		uwsgi_log("[uwsgi-cares] error: %s\n", ares_strerror(ret));
		exit(1);
	}
	struct uwsgi_route_var *urv = uwsgi_register_route_var("dns", uwsgi_route_var_dns_a);
        urv->need_free = 1;
}

struct uwsgi_plugin cares_plugin = {
	.name = "cares",
	.options = cares_options,
	.on_load = cares_register,
};
