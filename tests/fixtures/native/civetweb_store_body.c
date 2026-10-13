/* Pattern from civetweb unittest/public_server.c (validation run, AttackMap#189). */
#include "civetweb.h"

static int store_body_handler(struct mg_connection *conn, void *unused)
{
	char path[4096] = {0};
	const struct mg_request_info *info = mg_get_request_info(conn);
	(void)unused;
	sprintf(path, "./%s", info->local_uri);
	return mg_store_body(conn, path) > 0 ? 200 : 500;
}

/* Negative, from civetweb examples/embed_certificate: the URI length is
 * checked before the sprintf. */
static int hello_handler(struct mg_connection *conn, void *unused)
{
	char response[1024];
	const struct mg_request_info *ri = mg_get_request_info(conn);
	size_t uri_len = strlen(ri->local_uri);
	(void)unused;
	if (uri_len <= 100) {
		sprintf(response, "Hello at %s\n", ri->local_uri);
	}
	mg_printf(conn, "%s", response);
	return 200;
}
