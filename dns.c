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
	${dns[0:HTTP_HOST]}
	${dns[1:HTTP_HOST]}
	${dns[r:HTTP_HOST]}

	${dns_txt[r:HTTP_HOST]}

	${dns_ptr[r:REMOTE_ADDR]}

	${dns[a:HTTP_HOST]}
*/

static struct uwsgi_cares {
	int initialized;
	int timeout;
	char *cache;
	int ttl;
} ucares;

struct uwsgi_cares_query {
	int cb_done;
	int ok;
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
	// TODO cache the result ?

	// ok
	ucq->ok = 1;
}

static char *dns_get_a(char *name, uint16_t name_len, uint16_t *ip_len) {
	char *result = NULL;
	ares_channel channel;
	ares_socket_t socks[ARES_GETSOCK_MAXNUM];

	int ret = ares_init(&channel);
	if (ret) {
		uwsgi_log("[uwsgi-cares] error: %s\n", ares_strerror(ret));
		return NULL;
	}

	struct uwsgi_cares_query ucq;
	memset(&ucq, 0, sizeof(struct uwsgi_cares_query));
	ucq.ub = uwsgi_buffer_new(INET_ADDRSTRLEN);

	char *domain_name = uwsgi_concat2n(name, name_len, "", 0);
	ares_query(channel, domain_name, ns_c_in, ns_t_a, dns_a_cb, &ucq);
	free(domain_name);
	
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

	if (ucq.cb_done && ucq.ok) {
		*ip_len = ucq.ub->pos;
		result = ucq.ub->buf;
		// protect the buffer from being destroyed
		ucq.ub->buf = NULL;
	}
	
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
	.on_load = cares_register,
};
