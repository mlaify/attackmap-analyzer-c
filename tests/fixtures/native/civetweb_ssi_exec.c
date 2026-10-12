/* Pattern from civetweb src/civetweb.c do_ssi_exec (validation run, AttackMap#189). */
#include <stdio.h>

static void ssi_exec(struct mg_connection *conn, char *tag)
{
	char cmd[1024] = "";
	if (sscanf(tag, " \"%1023[^\"]\"", cmd) == 1) {
		FILE *fp = popen(cmd, "r");
		if (fp != NULL) {
			pclose(fp);
		}
	}
}

/* Negative, from civetweb src/civetweb.c: width-limited fields copied into a
 * heap buffer with a margin check. */
static int rewrite_passwords(FILE *fp, char *temp_file, size_t temp_buf_len)
{
	char line[512], u[256], d[256], h[256];
	size_t offs = 0;
	while (fgets(line, sizeof(line), fp) != NULL && (offs + 600) < temp_buf_len) {
		if (sscanf(line, "%255[^:]:%255[^:]:%255s", u, d, h) != 3) {
			continue;
		}
		offs += (size_t)sprintf(temp_file + offs, "%s:%s:%s\n", u, d, h);
	}
	return (int)offs;
}
