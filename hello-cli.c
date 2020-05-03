/*
 * The hello-cli demo program
 *
 * This file is part of the "u2up-cli" software project.
 *
 *  Copyright (C) 2020 Samo Pogacnik <samo_pogacnik@t-2.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
*/

#ifndef U2UP_CLI_FILE_hello_cli_c
#define U2UP_CLI_FILE_hello_cli_c
#else
#error Preprocesor macro U2UP_CLI_FILE_hello_cli_c conflict!
#endif

#define _GNU_SOURCE

#if 0
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <u2up-cli/u2up-clisrv.h>
#include <u2up-cli/u2up-clicli.h>

#define U2UP_LOG_NAME DEMO_CLI
#include <u2up-log/u2up-log.h>
/* Declare all other used "u2up-log" modules: */
U2UP_LOG_DECLARE(U2CLICLI);
U2UP_LOG_DECLARE(U2CLISRV);

/*
 * The MAIN part.
 */

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-q, --quiet              Disable all output.\n");
	printf("\t-p, --no-module NAME     Disable all output from u2up_log module NAME prefix.\n");
	printf("\t-v, --verbose            Enable verbose output.\n");
#if (U2UP_LOG_MODULE_TRACE != 0)
	printf("\t-t, --trace              Enable trace output.\n");
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
	printf("\t-g, --debug              Enable debug output.\n");
#endif
	printf("\t-s, --syslog             Enable syslog output (instead of stdout, stderr).\n");
	printf("\t-n, --no-header          No U2UP_LOG header added to every u2up_log_... output.\n");
	printf("\t-h, --help               Displays this text.\n");
}

static int usage_check(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"quiet", 0, 0, 'q'},
			{"no-module", 1, 0, 'p'},
			{"verbose", 0, 0, 'v'},
#if (U2UP_LOG_MODULE_TRACE != 0)
			{"trace", 0, 0, 't'},
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
			{"debug", 0, 0, 'g'},
#endif
			{"no-header", 0, 0, 'n'},
			{"syslog", 0, 0, 's'},
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qp:vltgnsh", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE == 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qp:vlgnsh", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "qp:vltnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "qp:vlnsh", long_options, &option_index);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			U2UP_LOG_SET_NORMAL(0);
			U2UP_LOG_SET_NORMAL2(U2CLICLI, 0);
			U2UP_LOG_SET_NORMAL2(U2CLISRV, 0);
			break;

		case 'v':
			U2UP_LOG_SET_VERBOSE(1);
			U2UP_LOG_SET_VERBOSE2(U2CLICLI, 1);
			U2UP_LOG_SET_VERBOSE2(U2CLISRV, 1);
			break;

		case 'p': {
				size_t optlen = strlen(optarg);
//tst:				printf("no-module: optlen=%zd, optarg=%s\n", optlen, optarg);
				if (strlen(U2UP_LOG_GET_NAME()) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME(), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET(1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(U2CLICLI)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(U2CLICLI), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(U2CLICLI, 1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(U2CLISRV)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(U2CLISRV), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(U2CLISRV, 1);
					}
			}
			break;

#if (U2UP_LOG_MODULE_TRACE != 0)
		case 't':
			U2UP_LOG_SET_TRACE(1);
			U2UP_LOG_SET_TRACE2(U2CLICLI, 1);
			U2UP_LOG_SET_TRACE2(U2CLISRV, 1);
			break;
#endif

#if (U2UP_LOG_MODULE_DEBUG != 0)
		case 'g':
			U2UP_LOG_SET_DEBUG(1);
			U2UP_LOG_SET_DEBUG2(U2CLICLI, 1);
			U2UP_LOG_SET_DEBUG2(U2CLISRV, 1);
			break;
#endif

		case 'n':
			U2UP_LOG_SET_HEADER(0);
			U2UP_LOG_SET_HEADER2(U2CLICLI, 0);
			U2UP_LOG_SET_HEADER2(U2CLISRV, 0);
			break;

		case 's':
			U2UP_LOG_SET_SYSLOG(1);
			U2UP_LOG_SET_SYSLOG2(U2CLICLI, 1);
			U2UP_LOG_SET_SYSLOG2(U2CLISRV, 1);
			break;

		case 'h':
			usage_help(argv);
			exit(EXIT_SUCCESS);

		case '?':
			exit(EXIT_FAILURE);
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

static int *clisd;
static int *srvsd;
static clisrv_pconn_struct *pconn;

static char *clisrv_cmds[] = {
	"test1 {a=%8x|b=%u} {c|d}",
	"test2 {a} {b} {c}",
	"test3 {a=%d | b|c}|{d | e}",
	NULL
};

static int test1_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int test2_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int test3_handle(clisrv_token_struct *curr_tokens, char *buff, int size);

static int (*cmd_handle[])(clisrv_token_struct *curr_tokens, char *buff, int size) = {
	test1_handle,
	test2_handle,
	test3_handle,
};

static int test1_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *a_token;
	clisrv_token_struct *b_token;
	clisrv_token_struct *c_token;
	clisrv_token_struct *d_token;
	uint32_t a;
	unsigned int b;

	printf("test1 command handle called!'\n");
	if ((a_token = getCurrentToken(curr_tokens, "a")) != NULL) {
		if ((a_token->eqval != NULL) && (strlen(a_token->eqval) > 0)) {
			sscanf(a_token->eqval, a_token->eqspec, &a);
		}
		printf("test1 command parameter (a=%.8x)!'\n", a);
	} else
	if ((b_token = getCurrentToken(curr_tokens, "b")) != NULL) {
		if ((b_token->eqval != NULL) && (strlen(b_token->eqval) > 0)) {
			sscanf(b_token->eqval, b_token->eqspec, &b);
		}
		printf("test1 command parameter (b=%u)!'\n", b);
	} else
		return -3;

	if ((c_token = getCurrentToken(curr_tokens, "c")) != NULL) {
		printf("test1 command parameter (c)!'\n");
	} else
	if ((d_token = getCurrentToken(curr_tokens, "d")) != NULL) {
		printf("test1 command parameter (d)!'\n");
	} else
		return -3;

	return 0;
}

static int test2_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("test2 command handle called!'\n");
	return 0;
}

static int test3_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("test3 command handle called!'\n");
	return 0;
}

static int socketSendReceive(int sock, char *snd_str, char *rcv_buf, size_t rcv_buf_size)
{
	int rv = 0, srv_rcvsz = 0;
	char buffer[CLISRV_MAX_CMDSZ];
	u2up_log_info("(entry) sock=%d\n", sock);

	/* Send cmd-data string over the connection socket (including terminating null byte) */
	rv = send(sock, snd_str, strlen(snd_str) + 1, 0);
	if (rv != strlen(snd_str) + 1) {
		u2up_log_system_error("send()\n");
		return -1;
	}
	u2up_log_debug("%d bytes sent\n", rv);

#if 1 /* Simulate server side! */
	/* srv_rcv_data: including '\0' string termination if all data received */
	while ((srv_rcvsz += recv(*srvsd, buffer, sizeof(buffer), 0)) < 0) {
		if (errno != EWOULDBLOCK) {
			u2up_log_system_error("recv()\n");
			return -1;
		}
		continue;
	}

	u2up_log_debug("srv: %d bytes received\n", srv_rcvsz);

	/* Parse received data */
	if ((rv = parseReceivedData(pconn, buffer, srv_rcvsz)) < 0) {
		u2up_log_error("parseReceivedData()\n");
		return -1;
	}

	/* Send response data (including terminating null byte) back to the client */
	if ((rv = send(*srvsd, pconn->snd, pconn->sndsz, 0)) < 0) {
		u2up_log_system_error("send()\n");
		return -1;
	}
#endif

	/* Receive data from the connection socket (including terminating null byte) */
	rv = recv(sock, rcv_buf, rcv_buf_size, 0);
	if (rv <= 0) {
		u2up_log_system_error("recv()\n");
		return -1;
	}
	u2up_log_debug("%d bytes received\n", rv);

	return 0;
}

int main(int argc, char *argv[])
{
	int rv;
	int sd[2];
	int flags;
	usage_check(argc, argv);

	if ((clisrv_pcmds = tokenizeCliCmds(clisrv_cmds)) == NULL) {
		u2up_log_error("tokenizeCliCmds() failed!\n");
		exit(EXIT_FAILURE);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sd) == -1) {
		u2up_log_system_error("socketpair()\n");
		exit(EXIT_FAILURE);
	}

	clisd = &sd[0];
	srvsd = &sd[1];

	/* Set server side socket nonblocking */
	if ((flags = fcntl(*srvsd, F_GETFL, 0)) < 0) {
		u2up_log_system_error("fcntl()\n");
		close(sd[0]);
		close(sd[1]);
		exit(EXIT_FAILURE);
	}

	if ((rv = fcntl(*srvsd, F_SETFL, flags | O_NONBLOCK)) < 0) {
		u2up_log_system_error("fcntl()\n");
		close(sd[0]);
		close(sd[1]);
		exit(EXIT_FAILURE);
	}

	/* Initialize internal client-server connection structure */
	if ((pconn = (clisrv_pconn_struct *)calloc(1, sizeof(clisrv_pconn_struct))) == NULL) {
		u2up_log_system_error("calloc() - pconn\n");
		close(sd[0]);
		close(sd[1]);
		exit(EXIT_FAILURE);
	}

	/* Initialize History-log file (and trim to the last 100 lines) */
	if (initCmdLineLog(".u2up_cli.log", 10) < 0) {
		u2up_log_error("initCmdLineLog()\n");
		close(sd[0]);
		close(sd[1]);
		exit(EXIT_FAILURE);
	}

	/* Process CLI commands */
	if (processCliCmds(*clisd, socketSendReceive) < 0) {
		u2up_log_error("processCliCmds()\n");
		close(sd[0]);
		close(sd[1]);
		exit(EXIT_FAILURE);
	}

	close(sd[0]);
	close(sd[1]);
	exit(EXIT_SUCCESS);
}

