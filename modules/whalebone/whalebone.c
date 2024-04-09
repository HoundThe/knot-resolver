#include "lib/defines.h"
#include "lib/layer.h"
#include "lib/log.h"
#include "lib/module.h"
#include "lib/resolve.h"
#include <libknot/dname.h>
#include <libknot/libknot.h>
#include <stdlib.h>
#include <string.h>

static int whalebone_filter(kr_layer_t *ctx)
{
	if (!ctx || !ctx->req) {
		return kr_ok();
	}

	const struct kr_request *req = ctx->req;

	/* Run the filter only on finished queries with source IP */
	if (!(ctx->state & KR_STATE_DONE) || !req->qsource.addr) {
		return ctx->state;
	}

	const struct sockaddr *addr = req->qsource.addr;
	/* Work only with IPv4 */
	if (addr->sa_family != AF_INET) {
		return ctx->state;
	}

	const char *ip_bytes = kr_inaddr(addr);
	char src_ip_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, ip_bytes, src_ip_str, sizeof(src_ip_str));

	kr_log_notice(DEVEL, "Source IP address: %s\n", src_ip_str);

	static const char *blacklist_ip = "127.0.0.1";
	/* Run the IP blacklist */
	if (strcmp(src_ip_str, blacklist_ip) == 0) {
		kr_log_notice(DEVEL, "Dropping response, reason: blacklisted IP\n");
		/* Unsure if this is proper way to drop packet */
		ctx->state = KR_STATE_FAIL;
		ctx->req->options.NO_ANSWER = 1;
		return ctx->state;
	}

	if (!req->answer) {
		return ctx->state;
	}

	const knot_dname_t *raw_domain = knot_pkt_qname(req->answer);
	char *domain_name = knot_dname_to_str_alloc(raw_domain);

	kr_log_notice(DEVEL, "Resolved name: %s\n", domain_name);

	const char *blacklist_domain = "youtube.com.";
	/* Run the domain blacklist */
	if (strcmp(blacklist_domain, domain_name) == 0) {
		kr_log_notice(DEVEL, "Dropping response, reason: blacklisted domain\n");
		ctx->state = KR_STATE_FAIL;
		ctx->req->options.NO_ANSWER = 1;
	}

	free(domain_name);
	return ctx->state;
}

KR_EXPORT
int whalebone_init(struct kr_module *module)
{
	/* .finish layer was set in specification */
	static kr_layer_api_t layer = {.finish = &whalebone_filter};
	module->layer = &layer;
	return kr_ok();
}

KR_MODULE_EXPORT(whalebone)
