/*
 * The u2up-clisrv Command Line Interface module (server side)
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

#ifndef U2UP_CLI_FILE_u2up_clisrv_h
#define U2UP_CLI_FILE_u2up_clisrv_h

#ifndef _GNU_SOURCE
#error You need to define _GNU_SOURCE macro before including any headers in the relevant C file!
#endif

#include <stdlib.h>
#include <string.h>

#include <u2up-cli/u2up-cli.h>

typedef struct clisrv_pconn {
	char *rcv;
	int rcvlen; /*without termination null character - alias strlen()*/
	char *tokens;
	int nr_tokens;
	char *snd;
	size_t sndsz; /*size of the send data including '\0'*/
} clisrv_pconn_struct;

struct clisrv_conn {
	clisrv_pconn_struct * pconn;
};

static struct clisrv_conn *clisrvConns;

enum clisrv_auto_cmdline {
	CLISRV_AUTO_COMPLETE = 0,
	CLISRV_AUTO_SUGGEST
};

enum clisrv_cmd_types {
	CLISRV_CMD = 0,
	CLISRV_ARG,
	CLISRV_VAL,
	CLISRV_EQUALS,
	CLISRV_SQUARE_L,
	CLISRV_SQUARE_R,
	CLISRV_CURLY_L,
	CLISRV_CURLY_R,
	CLISRV_VERTBAR
};

typedef struct clisrv_token clisrv_token_struct;
struct clisrv_token {
	clisrv_token_struct *base;
	clisrv_token_struct *next;
	int type; /*(command, argument, value, CTRL)*/
	int level;
	int mand;
	int opti;
	int altr;
	char *strval;
	char *eqspec;
	char eqval[100];
};

typedef struct clisrv_cmd clisrv_cmd_struct;
struct clisrv_cmd {
	clisrv_cmd_struct *next;
	char *cmd;
	int cmdsz;
	clisrv_token_struct *tokens;
	int nr_tokens;
	int (*cmd_handle)(clisrv_token_struct *curr_tokens, char *buff, int size);
};

typedef struct clisrv_cmds {
	clisrv_cmd_struct *first;
	char **clicmds;
	int nr_cmds;
} clisrv_cmds_struct;

static clisrv_cmds_struct *clisrv_pcmds;

static int (*cmd_handle[])(clisrv_token_struct *curr_tokens, char *buff, int size);

static int pconnCmdRemoveToken(clisrv_pconn_struct *pconn, char *token)
{
	char *next_token;
	int i, remain;

	if (pconn == NULL)
		return -1;

	if (token == NULL)
		return -1;

	if (pconn->nr_tokens <= 0)
		return -1;

	if ((token < pconn->tokens) || ((token - pconn->tokens) > (pconn->rcvlen + 1)))
		return -1;

	next_token = token + (strlen(token) + 1);
	remain = pconn->tokens + pconn->rcvlen + 1 - next_token;

#if 1
	u2up_log_debug("1 - pconn->nr_tokens=%d: ", pconn->nr_tokens);
	{
		int rv = 0;
		char *cmd_token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			u2up_log_debug("'%s' ", cmd_token);
			cmd_token += (strlen(cmd_token) + 1);
			rv++;
		}
		u2up_log_debug("\n");
	}
#endif
	for (i = 0; i < remain; i++) {
		token[i] = next_token[i];
	}
	pconn->nr_tokens--;
#if 1
	u2up_log_debug("2 - pconn->nr_tokens=%d: ", pconn->nr_tokens);
	{
		int rv = 0;
		char *cmd_token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			u2up_log_debug("'%s' ", cmd_token);
			cmd_token += (strlen(cmd_token) + 1);
			rv++;
		}
		u2up_log_debug("\n");
	}
#endif

	return 0;
}

void freePcmdCurrentTokens(clisrv_token_struct **curr_tokens)
{
	u2up_log_info("freePcmdCurrentTokens: entry\n");
	/* Recursive freing */
	if (curr_tokens != NULL) {
		if (*curr_tokens != NULL) {
			while ((*curr_tokens)->next != NULL) {
				freePcmdCurrentTokens(&((*curr_tokens)->next));
				(*curr_tokens)->next = NULL;
			}
			free(*curr_tokens);
			*curr_tokens = NULL;
		}
	}
}

static clisrv_token_struct * clisrvCheckAndSetCommand(clisrv_token_struct *pcmd_token, clisrv_pconn_struct *pconn)
{
	clisrv_token_struct *new;

	if (pcmd_token == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

	if (pconn->nr_tokens == 0)
		return NULL;

	if (strcmp(pcmd_token->strval, pconn->tokens) != 0)
		return NULL;

	if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
		u2up_log_system_error("calloc() - clisrv_token_struct: command\n");
		abort();
	}

	new->type = CLISRV_CMD;
	new->strval = pcmd_token->strval;
	pconnCmdRemoveToken(pconn, pconn->tokens);

	return new;
}

static clisrv_token_struct * clisrvCheckAndSetArgument(clisrv_token_struct *pcmd_token, clisrv_pconn_struct *pconn, clisrv_token_struct *curr_tokens)
{
	clisrv_token_struct *last;
	char *token, *eq;
	int i;

	if (pcmd_token == NULL)
		return NULL;

	if (curr_tokens == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

#if 0
	if (pcmd_token->opti <= pcmd_token->mand)
		if (pconn->nr_tokens == 0)
			return NULL;
#endif
#if 0
	u2up_log_debug("(pcmd_token=%p) '%s'\n", pcmd_token, pcmd_token->strval);
	u2up_log_debug(" level=%d\n", pcmd_token->level);
	u2up_log_debug(" mand=%d\n", pcmd_token->mand);
	u2up_log_debug(" opti=%d\n", pcmd_token->opti);
	u2up_log_debug(" altr=%d\n", pcmd_token->altr);
	u2up_log_debug("\n");
#endif

	last = curr_tokens;
	while (last->next != NULL) {
		last = last->next;
	}

#if 0
	u2up_log_debug("(last=%p) '%s'\n", last, last->strval);
	u2up_log_debug(" level=%d\n", last->level);
	u2up_log_debug(" mand=%d\n", last->mand);
	u2up_log_debug(" opti=%d\n", last->opti);
	u2up_log_debug(" altr=%d\n", last->altr);
	u2up_log_debug("\n");
#endif

	if (pconn->nr_tokens == 0) {
		if ((pcmd_token->opti <= pcmd_token->mand) && (pcmd_token->altr == 0)) {
			/*ERROR: mandatory command arguments required, but no more pconn tokens provided */
			u2up_log_debug("mandatory command arguments required, but no more pconn tokens provided\n");
			return NULL;
		}
	}

	i = pconn->nr_tokens;
	token = pconn->tokens;
	while (i > 0) {
		if (strncmp(token, pcmd_token->strval, strlen(pcmd_token->strval)) == 0) {

			if ((last->next = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: argument\n");
				abort();
			}

			last->next->type = CLISRV_ARG;
			last->next->strval = pcmd_token->strval;
			last->next->level = pcmd_token->level;
			last->next->mand = pcmd_token->mand;
			last->next->opti = pcmd_token->opti;
			last->next->altr = pcmd_token->altr;
			if ((last->next->altr != 0) && (last->next->altr == last->altr)) {
				/*ERROR: more than one alternative arguments provided*/
				u2up_log_debug("more than one alternative arguments provided\n");
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
			if ((eq = strchr(token, '=')) != NULL) {
				/*argument with value provided*/
				if ((pcmd_token->next != NULL) && (pcmd_token->next->type == CLISRV_EQUALS)) {
					if ((pcmd_token->next->next != NULL) && (pcmd_token->next->next->type == CLISRV_VAL)) {
						last->next->altr = pcmd_token->next->next->altr;
						last->next->eqspec = pcmd_token->next->next->strval;
						eq++;
						if (strlen(eq) < 100) {
							strncpy(last->next->eqval, eq, 100);
						} else {
							/*ERROR: value string too long*/
							u2up_log_debug("argument value string too long\n");
							freePcmdCurrentTokens(&curr_tokens);
							return NULL;
						}
					} else {
						/*ERROR: value required, but value specification missing*/
						u2up_log_debug("argument value required, but value specification missing\n");
						freePcmdCurrentTokens(&curr_tokens);
						return NULL;
					}
				} else {
					/*ERROR: value not required, but provided*/
					u2up_log_debug("argument value provided, but none required\n");
					freePcmdCurrentTokens(&curr_tokens);
					return NULL;
				}
			} else {
				/*argument without provided value*/
				if ((pcmd_token->next != NULL) && (pcmd_token->next->type == CLISRV_EQUALS)) {
					/*ERROR: value required, but none provided*/
					u2up_log_debug("argument value required, but none provided\n");
					freePcmdCurrentTokens(&curr_tokens);
					return NULL;
				}
				last->next->eqval[0] = '\0';
			}
			pconnCmdRemoveToken(pconn, token);
			break;
		}
		i--;
		token += (strlen(token) + 1);
	}

	return curr_tokens;
}

clisrv_token_struct * checkSyntaxAndSetValues(clisrv_cmd_struct *this, clisrv_pconn_struct *pconn)
{
	clisrv_token_struct *pcmd_token;
	clisrv_token_struct *curr_tokens;

	if (this == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

	/* Analyse command token */
	pcmd_token = this->tokens;
	if (pcmd_token->type != CLISRV_CMD) {
		return NULL;
	}
	if ((curr_tokens = clisrvCheckAndSetCommand(pcmd_token, pconn)) == NULL) {
		return NULL;
	}

	/* Analyse command argument tokens: walk through command specification! */
	while (U2UP_CLI_TRUE) {
		pcmd_token = pcmd_token->next;
		if (pcmd_token == NULL) {
			/* We got through command template! */
			if (pconn->nr_tokens != 0) {
				/* pconn tokens remaining: unknown cmd arguments */
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
			return curr_tokens;
		}

		/* Error check - just in case */
		if (pcmd_token->type == CLISRV_CMD) {
			u2up_log_error("CLISRV_CMD should not be detected here!\n");
			freePcmdCurrentTokens(&curr_tokens);
			return NULL;
		}
		/* Skip! */
		if (pcmd_token->type != CLISRV_ARG) {
			continue;
		}

#if 0
		/* mandatory command arguments required, but no more pconn tokens provided */
		if (pcmd_token->opti <= pcmd_token->mand) {
			if (pconn->nr_tokens == 0) {
				/* no more pconn tokens: missing cmd arguments */
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
		}
#endif
		/* Still not through command template! */
		if (pcmd_token->type != CLISRV_ARG) {
			u2up_log_error("Only CLISRV_ARG should be detected here (type=%d)!\n", pcmd_token->type);
			freePcmdCurrentTokens(&curr_tokens);
			return NULL;
		}

		if ((curr_tokens = clisrvCheckAndSetArgument(pcmd_token, pconn, curr_tokens)) == NULL) {
			return NULL;
		}
	}

	return curr_tokens;
}

static clisrv_token_struct * getCurrentToken(clisrv_token_struct *curr_tokens, char *strval)
{
	clisrv_token_struct *curr_token;

	if (curr_tokens == NULL)
		return NULL;

	if (strval == NULL)
		return NULL;

	if (strlen(strval) == 0)
		return NULL;

	curr_token = curr_tokens;
	while (curr_token != NULL) {
		if ((curr_token->strval != NULL) && (strlen(curr_token->strval) > 0)) {
			if (strcmp(curr_token->strval, strval) == 0) {
				break;
			}
		}
		curr_token = curr_token->next;
	}

	return curr_token;
}

static char * squeezeStrIfBegin(char *str, char c)
{
	int squeeze;
	char *begin = str;
	char *tmp;
	
	if (str == NULL)
		return NULL;

	do {
		squeeze = 0;
		if (*begin == c)
			squeeze = 1;

		if (squeeze != 0) {
			tmp = begin;
			while (*tmp != '\0') {
				*tmp = *(tmp + 1);
				tmp++;
			}
		}
	} while (squeeze != 0);

	return begin;
}

static char * squeezeStrIfNext(char *str, char c)
{
	int squeeze;
	char *next = str + 1;
	char *tmp;
	
	if (str == NULL)
		return NULL;

	do {
		squeeze = 0;
		if (*next == c)
			squeeze = 1;

		if (squeeze != 0) {
			tmp = next;
			while (*tmp != '\0') {
				*tmp = *(tmp + 1);
				tmp++;
			}
		}
	} while (squeeze != 0);

	return next;
}

static clisrv_token_struct * tokenizeCmdStr(clisrv_cmd_struct *clicmd)
{
	char *tmp;
	int level = 0;
	int mand = 0;
	int opti = 0;
	int altr = 0;
	int altr_last = 0;
	int token_on;
	clisrv_token_struct *new;
	clisrv_token_struct *base = NULL;
	clisrv_token_struct *current;
	clisrv_token_struct *curr_base;
	u2up_log_info("(entry)\n");

	if (clicmd == NULL) {
		u2up_log_error("Invalid argument clicmd=%p\n", clicmd);
		return NULL;
	}

	u2up_log_debug("tokenizeCmdStr clicmd->cmd: %s\n", clicmd->cmd);

	tmp = clicmd->cmd;
	token_on = U2UP_CLI_FALSE;
	while (*tmp != '\0') {
		u2up_log_debug("tokenizeCmdStr tmp: %s\n", tmp);
		if (*tmp == '{') {
			level++;
			mand = level;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: left curly bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_CURLY_L;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_CURLY_L)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;

			current = new;
		}
		if (*tmp == '}') {
			level--;
			mand = level;
			if (altr > 0)
				altr_last = altr;
			altr = 0;
			if (level < 0) {
				u2up_log_error("Syntax error - curly brackets: more rights then lefts\n");
				abort();
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: right curly bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_CURLY_R;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_CURLY_R)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
			curr_base = current->base;
			while (curr_base->type != CLISRV_CURLY_L) {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			}
			if (curr_base->type != CLISRV_CURLY_L) {
				u2up_log_error("Syntax error - curly brackets: left not found\n");
				abort();
			}
			new->base = curr_base;
			if (new->level != (new->base->level - 1)) {
				u2up_log_error("Syntax error - curly brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '[') {
			level++;
			opti = level;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: left square bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_SQUARE_L;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_SQUARE_L)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;

			current = new;
		}
		if (*tmp == ']') {
			level--;
			opti = level;
			if (altr > 0)
				altr_last = altr;
			altr = 0;
			if (level < 0) {
				u2up_log_error("Syntax error - square brackets: more rights then lefts\n");
				abort();
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: right square bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_SQUARE_R;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_SQUARE_R)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
			curr_base = current->base;
			while (curr_base->type != CLISRV_SQUARE_L) {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			}
			if (curr_base->type != CLISRV_SQUARE_L) {
				u2up_log_error("Syntax error - square brackets: left not found\n");
				abort();
			}
			new->base = curr_base;
			if (new->level != (new->base->level - 1)) {
				u2up_log_error("Syntax error - square brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '|') {
			if (altr == 0) {
				altr = altr_last + 1;
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: vertbar\n");
				abort();
			}
			current->next = new;
			current->altr = altr;
			new->type = CLISRV_VERTBAR;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_VERTBAR)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
			curr_base = current;
			do {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			} while (
				(curr_base->type == CLISRV_VERTBAR) ||
				(curr_base->type == CLISRV_ARG)
			);
			new->base = curr_base;
			if (
				(curr_base->type == CLISRV_VERTBAR) ||
				(curr_base->type == CLISRV_ARG)
			) {
				u2up_log_error("Syntax error - verbar\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '=') {
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				u2up_log_system_error("calloc() - clisrv_token_struct: equals\n");
				abort();
			}
			current->next = new;
			new->type = CLISRV_EQUALS;
			u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_EQUALS)\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
			new->base = current;
			if (new->base->type != CLISRV_ARG) {
				u2up_log_error("Syntax error - equals\n");
				abort();
			}

			current = new;
		}
		switch (*tmp) {
		case ' ':
		case '{':
		case '}':
		case '[':
		case ']':
		case '|':
		case '=':
			token_on = U2UP_CLI_FALSE;
			squeezeStrIfNext(tmp, ' ');
			*tmp = '\0';
			break;
		default:
			if (token_on == U2UP_CLI_FALSE) {
				token_on = U2UP_CLI_TRUE;
				if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
					u2up_log_system_error("calloc() - clisrv_token_struct: strval\n");
					abort();
				}
				if (base == NULL) {
					base = new;
					new->base = new;
					new->type = CLISRV_CMD;
					u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_CMD)\n", new->type);
				} else {
					current->next = new;
					new->base = current;
					if (new->base->type != CLISRV_EQUALS) {
						new->type = CLISRV_ARG;
						u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_ARG)\n", new->type);
						if (new->base->type != CLISRV_VERTBAR) {
							if (altr > 0)
								altr_last = altr;
							altr = 0;
						}
					} else {
						new->type = CLISRV_VAL;
						u2up_log_debug("tokenizeCmdStr new->type: %d (CLISRV_VAL)\n", new->type);
					}
				}
				new->level = level;
				new->mand = mand;
				new->opti = opti;
				new->altr = altr;
				new->strval = tmp;
				u2up_log_debug("tokenizeCmdStr new->strval: %s\n", new->strval);

				current = new;
			}
		}
		tmp++;
	}

	return base;
}

static clisrv_cmd_struct * tokenizeCliCmd(char *clicmd)
{
	clisrv_cmd_struct *tmp;
	u2up_log_info("(entry) clicmd=%p\n", clicmd);

	if (clicmd == NULL) {
		u2up_log_error("Invalid argument clicmd=%p\n", clicmd);
		return NULL;
	}

	if ((tmp = (clisrv_cmd_struct *)calloc(1, sizeof(clisrv_cmd_struct))) == NULL) {
		u2up_log_system_error("calloc() - clisrv_cmd_struct\n");
		return NULL;
	}
	tmp->cmdsz = strlen(clicmd) + 1;
	if ((tmp->cmd = (char *)calloc(tmp->cmdsz, sizeof(char))) == NULL) {
		u2up_log_system_error("calloc() - cmd string\n");
		return NULL;
	}
	memcpy(tmp->cmd, clicmd, tmp->cmdsz);
	if ((tmp->tokens = tokenizeCmdStr(tmp)) == NULL) {
		abort();
	}

#if 0 /*test init result*/
	{
		clisrv_token_struct *token = tmp->tokens;
		u2up_log_debug("pcmd tokens:\n");
		while (token != NULL) {
			u2up_log_debug("tokenize cmd: %s\n", clicmd);
			switch (token->type) {
			case CLISRV_CMD:
				u2up_log_debug("COMMAND:\n");
				break;
			case CLISRV_ARG:
				u2up_log_debug("ARGUMENT NAME:\n");
				break;
			case CLISRV_VAL:
				u2up_log_debug("ARGUMENT VALUE:\n");
				break;
			case CLISRV_EQUALS:
				u2up_log_debug("EQUALS:\n");
				break;
			case CLISRV_SQUARE_L:
				u2up_log_debug("OPTIONALY BEGIN:\n");
				break;
			case CLISRV_SQUARE_R:
				u2up_log_debug("OPTIONALY END:\n");
				break;
			case CLISRV_CURLY_L:
				u2up_log_debug("MANDATORY BEGIN:\n");
				break;
			case CLISRV_CURLY_R:
				u2up_log_debug("MANDATORY END:\n");
				break;
			case CLISRV_VERTBAR:
				u2up_log_debug("VERTBAR:\n");
				break;
			}
			u2up_log_debug("(%p) '%s'\n", token, token->strval);
			u2up_log_debug(" base=%p\n", token->base);
			u2up_log_debug(" next=%p\n", token->next);
			u2up_log_debug(" level=%d\n", token->level);
			u2up_log_debug(" mand=%d\n", token->mand);
			u2up_log_debug(" opti=%d\n", token->opti);
			u2up_log_debug(" altr=%d\n", token->altr);
			u2up_log_debug("\n");
			token = token->next;
		}
		u2up_log_debug("\n");
	}
#endif

	return tmp;
}

static clisrv_cmds_struct * tokenizeCliCmds(char *clicmds[])
{
	int i = 0;
	clisrv_cmd_struct **tmp;
	clisrv_cmds_struct *pcmds;
	u2up_log_info("(entry) clicmds=%p\n", clicmds);

	if (clicmds == NULL) {
		u2up_log_error("Invalid argument clicmds=%p\n", clicmds);
		return NULL;
	}

	if ((pcmds = (clisrv_cmds_struct *)calloc(1, sizeof(clisrv_cmds_struct))) == NULL) {
		u2up_log_system_error("calloc() - clisrv_cmds_struct\n");
		return NULL;
	}

	pcmds->clicmds = clicmds;
	while (clicmds[i] != NULL) {
		u2up_log_debug("cmd[%d]: %s\n", i, clicmds[i]);
		if (pcmds->first == NULL)
			tmp = &pcmds->first;
		if ((*tmp = tokenizeCliCmd(clicmds[i])) == NULL) {
			abort();
		}
		(*tmp)->cmd_handle = cmd_handle[i];
		tmp = &(*tmp)->next;
		i++;
	}
	pcmds->nr_cmds = i;
#if 0
	u2up_log_debug("nr_cmds=%d\n", pcmds->nr_cmds);
	tmp = &pcmds->first;
	i = 0;
	while ((*tmp) != NULL) {
		u2up_log_debug("cmd[%d]\n", i);
		tmp = &(*tmp)->next;
		i++;
	}
#endif

	return pcmds;
}

static int tokenizeCmdLine(clisrv_pconn_struct *pconn)
{
	char *tmp;
	u2up_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}
#if 1
	if ((tmp = (char *)reallocarray(pconn->tokens, (pconn->rcvlen + 1), sizeof(char))) == NULL) {
		u2up_log_return_system_err("realocarray() - tokens\n");
	}
#else
	free(pconn->tokens);
	pconn->tokens = NULL;
	if ((tmp = (char *)calloc((pconn->rcvlen + 1), sizeof(char))) == NULL) {
		u2up_log_return_system_err("calloc() - tokens\n");
	}
#endif
	memcpy(tmp, pconn->rcv, pconn->rcvlen + 1);
	pconn->tokens = tmp;
	pconn->nr_tokens = 0;
	while (*tmp != '\0') {
#if 0
		u2up_log_debug("tmp='%s'\n", tmp);
#endif
		switch (*tmp) {
		case ' ':
		case ',':
		case ';':
		case '\t':
		case '\n':
		case '\r':
			if (tmp == pconn->tokens) {
				squeezeStrIfBegin(tmp, *tmp);
			} else {
				int squeeze;
				char *next = tmp + 1;
				do {
					squeeze = U2UP_CLI_FALSE;
					switch (*next) {
					case ' ':
					case ',':
					case ';':
					case '\t':
						squeeze = U2UP_CLI_TRUE;
					}
					if (squeeze == U2UP_CLI_TRUE) {
						char *next_tmp = next;
						while (*next_tmp != '\0') {
							*next_tmp = *(next_tmp + 1);
							next_tmp++;
						}
					}
				} while (squeeze == U2UP_CLI_TRUE);
#if 0
				u2up_log_debug("tmp:'%s'\n", tmp);
#endif
				if (*(tmp + 1) == '=') {
					*tmp = '=';
					squeezeStrIfNext(tmp, *(tmp + 1));
					switch (*(tmp + 1)) {
					case ' ':
					case '\t':
						squeezeStrIfNext(tmp, *(tmp + 1));
					}
				} else if (*(tmp - 1) == '=') {
					switch (*tmp) {
					case ' ':
					case '\t':
						squeezeStrIfNext((tmp - 1), *tmp);
					}
				} else {
					*tmp = '\0';
					if ((tmp > pconn->tokens) && (*(tmp - 1) != '\0'))
						pconn->nr_tokens++;
				}
			}
		}
		tmp++;
	}
	return 0;
}

static int setCliCmdAutoSuggestByToken(clisrv_token_struct *pcmd_tokens, clisrv_pconn_struct *pconn, char *token, char *buff, int size)
{
	int braces = 0;
	int opt_part_found = 0;
	char *strval;
	clisrv_token_struct *pcmd_token;
	u2up_log_info("(entry)\n");

	if (pcmd_tokens == NULL) {
		u2up_log_error("Invalid argument pcmd_tokens=%p\n", pcmd_tokens);
		return -1;
	}

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (token == NULL) {
		u2up_log_error("Invalid argument token=%p\n", token);
		return -1;
	}

	u2up_log_debug("TEST: setCliCmdAutoSuggestByToken()\n");
	pcmd_token = pcmd_tokens->next;
	while (pcmd_token != NULL) {
		if (
			(pcmd_token->type != CLISRV_CMD) &&
			(pcmd_token->type != CLISRV_ARG)
		   ) {
			pcmd_token = pcmd_token->next;
			continue;
		}
		strval = pcmd_token->strval;
		u2up_log_debug("AutoSuggest - strval: '%s'\n", strval);
		u2up_log_debug("AutoSuggest - Comparing-opts: strval=%s, token=%s\n", strval, token);
		/* Force multi-match, if token empty! */
		if (strlen(token) == 0)
			opt_part_found++;
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				u2up_log_debug("AutoSuggest - opts - partially compared: strval=%s, token=%s\n", strval, token);
				opt_part_found++;
				u2up_log_debug("AutoSuggest - opts - buff-1: '%s'\n", buff);
#if 0
				if (strlen(strval) == strlen(token)) {
					opt_found = 1;
				}
#endif
			}
		}
		pcmd_token = pcmd_token->next;
	}

	if (opt_part_found > 0) {
		pcmd_token = pcmd_tokens->next;
		braces = 0;
		while (pcmd_token != NULL) {
			if (
				(pcmd_token->type != CLISRV_CMD) &&
				(pcmd_token->type != CLISRV_ARG)
			   ) {
				pcmd_token = pcmd_token->next;
				continue;
			}
			strval = pcmd_token->strval;
			u2up_log_debug("AutoSuggest - strval: '%s'\n", strval);
			if (braces == 0)
				clisrv_strncat(buff, "\n", size);
			u2up_log_debug("AutoSuggest - buff-2: '%s'\n", buff);
			if (
				(pcmd_token->base->type != CLISRV_CMD) &&
				(pcmd_token->base->type != CLISRV_ARG)
			) {
				switch (pcmd_token->base->type) {
				case CLISRV_SQUARE_L:
				case CLISRV_CURLY_L:
					braces++;
					pcmd_token = pcmd_token->base;
					break;
				default:
					pcmd_token = pcmd_token->next;
				};
				while ((braces > 0) && (pcmd_token != NULL)) {
					if (
						(pcmd_token->type != CLISRV_CMD) &&
						(pcmd_token->type != CLISRV_ARG) &&
						(pcmd_token->type != CLISRV_VAL)
					) {
						switch (pcmd_token->type) {
						case CLISRV_SQUARE_L:
							braces++;
//							clisrv_strncat(buff, "[", size);
							if ((strlen(buff) > 0) && (buff[strlen(buff) - 1] != '\n'))
								clisrv_strncat(buff, " [", size);
							else
								clisrv_strncat(buff, "[", size);
							break;
						case CLISRV_SQUARE_R:
							braces--;
							clisrv_strncat(buff, "]", size);
							break;
						case CLISRV_CURLY_L:
							braces++;
							u2up_log_debug("AutoSuggest - curly brace left: strlen(buff)=%ld, buff='%s'\n", strlen(buff), buff);
							if ((strlen(buff) > 0) && (buff[strlen(buff) - 1] != '\n'))
								clisrv_strncat(buff, " {", size);
							else
								clisrv_strncat(buff, "{", size);
							break;
						case CLISRV_CURLY_R:
							braces--;
							clisrv_strncat(buff, "}", size);
							break;
						case CLISRV_EQUALS:
							clisrv_strncat(buff, "=", size);
							break;
						case CLISRV_VERTBAR:
							clisrv_strncat(buff, " | ", size);
							break;
						};
					} else
						clisrv_strncat(buff, pcmd_token->strval, size);

					pcmd_token = pcmd_token->next;
				}
				continue;
			} else {
				clisrv_strncat(buff, strval, size);
				if (pcmd_token->next != NULL)
					if (pcmd_token->next->type == CLISRV_EQUALS)
						if (pcmd_token->next->next != NULL) {
							clisrv_strncat(buff, "=", size);
							clisrv_strncat(buff, pcmd_token->next->next->strval, size);
						}
			}

			u2up_log_debug("AutoSuggest - opts - buff-4: '%s'\n", buff);
			if (buff[strlen(buff) - 1] != '=')
				clisrv_strncat(buff, " ", size);
			u2up_log_debug("AutoSuggest - opts - buff-5: '%s'\n", buff);
			pcmd_token = pcmd_token->next;
		}
	}

	return opt_part_found;
}

static int setCliCmdAutoCompleteByToken(clisrv_token_struct *pcmd_tokens, clisrv_pconn_struct *pconn, char *token, char *buff, int size)
{
	int opt_found = 0;
	int opt_part_found = 0;
	char *strval;
	clisrv_token_struct *pcmd_token;
	u2up_log_info("(entry)\n");

	if (pcmd_tokens == NULL) {
		u2up_log_error("Invalid argument pcmd_tokens=%p\n", pcmd_tokens);
		return -1;
	}

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (token == NULL) {
		u2up_log_error("Invalid argument token=%p\n", token);
		return -1;
	}

	u2up_log_debug("TEST: setCliCmdAutoCompleteByToken()\n");
	pcmd_token = pcmd_tokens->next;
	while (pcmd_token != NULL) {
		if (
			(pcmd_token->type != CLISRV_CMD) &&
			(pcmd_token->type != CLISRV_ARG)
		   ) {
			pcmd_token = pcmd_token->next;
			continue;
		}
		strval = pcmd_token->strval;
		u2up_log_debug("%s\n", strval);
		u2up_log_debug("AutoComplete - Comparing-opts: strval=%s, token=%s\n", strval, token);
		/* Force multi-match, if token empty! */
		if (strlen(token) == 0)
			opt_part_found++;
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				u2up_log_debug("AutoComplete - opts - partially compared: strval=%s, token=%s\n", strval, token);
				opt_part_found++;
				u2up_log_debug("AutoComplete - opts - buff-1: '%s'\n", buff);

				if (strlen(strval) == strlen(token)) {
					opt_found = 1;
				}

				if (opt_part_found == 1) {
					clisrv_strncat(buff, &strval[strlen(token)], size);
					if (pcmd_token->next->type == CLISRV_EQUALS)
						clisrv_strncat(buff, "=", size);
					if (opt_found == 1)
						break;
				} else {
					int j = 0;
					do {
						if (buff[j] != strval[strlen(token) + j]) {
							buff[j] = '\0';
							break;
						}
						j++;
					} while (j < strlen(buff));
				}
			}
		}
		pcmd_token = pcmd_token->next;
	}

	return opt_part_found;
}

static int setCliCmdsResponseByTokens(clisrv_cmds_struct *pcmds, clisrv_pconn_struct *pconn, char *buff, int size, int mode)
{
	int i;
	int opt_part_found = 0;
	int cmd_found = 0;
	int cmd_part_found = 0;
	char *token;
	char *strval;
	clisrv_cmd_struct *pcmd;
	u2up_log_info("(entry)\n");

	if (pcmds == NULL) {
		u2up_log_error("Invalid argument pcmds=%p\n", pcmds);
		return -1;
	}

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	token = pconn->tokens;
	pcmd = pcmds->first;
	for (i = 0; i < pcmds->nr_cmds; i++) {
		strval = pcmd->tokens->strval;
		u2up_log_debug("%s\n", strval);
		u2up_log_debug("Comparing-cmds: mode=%d, strval=%s, token=%s\n", mode, strval, token);
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				u2up_log_debug("cmds - partially compared: strval=%s, token=%s\n", strval, token);
				cmd_part_found++;
				u2up_log_debug("cmds - buff-1: '%s'\n", buff);

				if (strlen(strval) == strlen(token)) {
					u2up_log_debug("buff-2: '%s'\n", buff);
					cmd_found = 1;
					break;
				}

				if (mode == CLISRV_AUTO_COMPLETE) {
					if (cmd_part_found == 1)
						clisrv_strncat(buff, &strval[strlen(token)], size);
					else {
						int j = 0;
						do {
							if (buff[j] != strval[strlen(token) + j]) {
								buff[j] = '\0';
								break;
							}
							j++;
						} while (j < strlen(buff));
					}
				}
				if (mode == CLISRV_AUTO_SUGGEST) {
					clisrv_strncat(buff, "\n", size);
					clisrv_strncat(buff, strval, size);

					u2up_log_debug("cmds - buff-4: '%s'\n", buff);
					clisrv_strncat(buff, " ", size);
					u2up_log_debug("cmds - buff-5: '%s'\n", buff);
				}
			}
		}
		pcmd = pcmd->next;
	}
	if (cmd_found != 0) {
		u2up_log_debug("fully compared: strval=%s, token(nr_tokens=%d)=%s\n", strval, pconn->nr_tokens, token);
		if (pconn->nr_tokens > 0) {
			i = 1;
			token += (strlen(token) + 1);
			while (i < pconn->nr_tokens) {
				if (mode == CLISRV_AUTO_COMPLETE) {
					opt_part_found = setCliCmdAutoCompleteByToken(pcmd->tokens, pconn, token, buff, size);
					u2up_log_debug("2 - opt_part_found=%d\n", opt_part_found);
					if (strncmp(strval, token, size) == 0)
						break;
				}
				i++;
				if (i >= pconn->nr_tokens)
					break;
				token += (strlen(token) + 1);
			}
			if (mode == CLISRV_AUTO_SUGGEST) {
				opt_part_found = setCliCmdAutoSuggestByToken(pcmd->tokens, pconn, token, buff, size);
				u2up_log_debug("3 - opt_part_found=%d\n", opt_part_found);
			}
		}
	}

	/* Adding additional space to auto-complete, if needed! */
	if (mode == CLISRV_AUTO_COMPLETE) {
		u2up_log_debug("checkend - pconn->rcv(sz=%ld): '%c' cmd_found=%d, cmd_part_found=%d, opt_part_found=%d\n",
				strlen(pconn->rcv), pconn->rcv[strlen(pconn->rcv) - 2], cmd_found, cmd_part_found, opt_part_found);
		u2up_log_debug("checkend - buff(len=%ld): '%c'\n", strlen(buff), buff[strlen(buff) - 1]);
		if (
			((cmd_part_found == 1) || (opt_part_found == 1)) &&
			(pconn->rcv[strlen(pconn->rcv) - 2] != ' ') &&
			(pconn->rcv[strlen(pconn->rcv) - 2] != '=') &&
			(strlen(buff) > 0) &&
			(buff[strlen(buff) - 1] != '=')
		) {
			u2up_log_debug("adding space 1\n");
			clisrv_strncat(buff, " ", size);
		} else if (
			((cmd_part_found == 1) && (opt_part_found == 1)) &&
			(pconn->rcv[strlen(pconn->rcv) - 2] != ' ') &&
			(pconn->rcv[strlen(pconn->rcv) - 2] != '=') &&
			(strlen(buff) == 0)
		) {
			u2up_log_debug("adding space 2\n");
			clisrv_strncat(buff, " ", size);
		} else if (
			((cmd_part_found == 1) && (opt_part_found == 0)) &&
			(pconn->rcv[strlen(pconn->rcv) - 2] != ' ') &&
			(pconn->nr_tokens == 1)
		) {
			u2up_log_debug("adding space 3\n");
			clisrv_strncat(buff, " ", size);
		}
	}

	cmd_part_found = opt_part_found;

	return cmd_part_found;
}

static int autoCmdLine(clisrv_pconn_struct *pconn, int mode)
{
	int rv = 0;
	u2up_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (mode == CLISRV_AUTO_SUGGEST)
		clisrv_strncat(pconn->snd, "<pre>", CLISRV_MAX_MSGSZ);

	if ((rv = setCliCmdsResponseByTokens(clisrv_pcmds, pconn, pconn->snd, CLISRV_MAX_MSGSZ, mode)) < 0) {
		u2up_log_error("setCliCmdResponseByTokens() failed\n");
		return -1;
	}

	switch (mode) {
	case CLISRV_AUTO_COMPLETE:
		u2up_log_debug("Auto-Complete(len=%ld):'%s'\n", strlen(pconn->snd), pconn->snd);
		u2up_log_debug("Auto-Complete(pconn->rcvlen=%d):'%s'\n", pconn->rcvlen, pconn->rcv);
		clisrv_strncat(pconn->snd, "\t", CLISRV_MAX_MSGSZ);
		u2up_log_debug("Auto-Complete-send(len=1):'%s'\n", pconn->snd);
		pconn->sndsz = strlen(pconn->snd) + 1;
		break;
	case CLISRV_AUTO_SUGGEST:
		{
			clisrv_strncat(pconn->snd, "</pre>", CLISRV_MAX_MSGSZ);
			clisrv_strncat(pconn->snd, pconn->rcv, CLISRV_MAX_MSGSZ);
			u2up_log_debug("Auto-Suggest(len=%ld, pconn->rcvlen=%d):'%s'\n", strlen(pconn->snd), pconn->rcvlen, pconn->snd);
			pconn->sndsz = strlen(pconn->snd) + 1;
		}
		break;
	}
	return 0;
}

static int execCliCmdsTokens(clisrv_cmds_struct *pcmds, clisrv_pconn_struct *pconn, char *buff, int size)
{
	int i;
	int cmd_found = 0;
	char *token;
	char *strval;
	clisrv_cmd_struct *pcmd;
	clisrv_token_struct *curr_tokens;
	u2up_log_info("(entry)\n");

	if (pcmds == NULL) {
		u2up_log_error("Invalid argument pcmds=%p\n", pcmds);
		return -1;
	}

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (pconn->nr_tokens == 0) {
		u2up_log_debug("Empty command\n");
		return 0;
	}

	token = pconn->tokens;
	pcmd = pcmds->first;
	/* First check command */
	for (i = 0; i < pcmds->nr_cmds; i++) {
		strval = pcmd->tokens->strval;
		u2up_log_debug("%s\n", strval);
		u2up_log_debug("Comparing-cmds: strval='%s', token='%s'\n", strval, token);
		if (strlen(strval) == strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				u2up_log_debug("command found: cmd='%s'\n", token);
				cmd_found = 1;
				break;
			}
		}
		pcmd = pcmd->next;
	}
	if (cmd_found == 0) {
		return -2;
	}

	if ((curr_tokens = checkSyntaxAndSetValues(pcmd, pconn)) == NULL) {
		if (pconn->nr_tokens == 0)
			clisrv_strncat(buff, "Missing command arguments!\n", CLISRV_MAX_MSGSZ);
		else
			clisrv_strncat(buff, "Unknown command arguments!\n", CLISRV_MAX_MSGSZ);
		return -3;
	}

	return pcmd->cmd_handle(curr_tokens, buff, size);
}

static int execCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0;
	int close_conn = 0;
	char buff[CLISRV_MAX_MSGSZ] = "";
	u2up_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		u2up_log_debug("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if ((rv = execCliCmdsTokens(clisrv_pcmds, pconn, buff, CLISRV_MAX_MSGSZ)) < 0) {
		u2up_log_debug("execCliCmdsTokens() failed (rv=%d)\n", rv);
		switch (rv) {
		case (-1):
			clisrv_strncat(buff, "error: invalid execution call (check code)", CLISRV_MAX_MSGSZ);
			break;
		case (-2):
			clisrv_strncat(buff, "error: unknown command", CLISRV_MAX_MSGSZ);
			break;
		case (-3):
			clisrv_strncat(buff, "error: invalid command syntax", CLISRV_MAX_MSGSZ);
			break;
		}
	} else {
		switch (rv) {
		case (127):
			clisrv_strncat(buff, "Bye...", CLISRV_MAX_MSGSZ);
			close_conn = 1;
			break;
		}
	}

	clisrv_strncat(pconn->snd, "<pre>", CLISRV_MAX_MSGSZ);
	clisrv_strncat(pconn->snd, buff, CLISRV_MAX_MSGSZ);
	clisrv_strncat(pconn->snd, "</pre>", CLISRV_MAX_MSGSZ);
	if (close_conn != 0) {
		clisrv_strncat(pconn->snd, "<quit>", CLISRV_MAX_MSGSZ);
	}
	u2up_log_debug("sending response: '%s'\n", pconn->snd);
	pconn->sndsz = strlen(pconn->snd) + 1;

	return 0;
}

static int parseCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0;
	u2up_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	tokenizeCmdLine(pconn);
#if 1
	u2up_log_debug("pconn->tokens=%s, pconn->nr_tokens=%d\n", pconn->tokens, pconn->nr_tokens);
	{
		char *token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			u2up_log_debug("%s\n", token);
			token += (strlen(token) + 1);
			rv++;
		}
	}
	rv = 0;
#endif

	u2up_log_debug("pconn->rcvlen=%d'\n", pconn->rcvlen);
	u2up_log_debug("pconn->rcv='%s'\n", pconn->rcv);
	if (pconn->rcvlen > 0) {
		if (pconn->rcv[pconn->rcvlen - 1] == '\t') {
			if (pconn->rcvlen > 1) {
				if (pconn->rcv[pconn->rcvlen - 2] == '\t') {
					pconn->rcv[pconn->rcvlen - 2] = '\0';
					pconn->rcvlen -= 2;
					/* Auto-suggest the cmdline */
					if ((rv = autoCmdLine(pconn, CLISRV_AUTO_SUGGEST)) < 0) {
						u2up_log_error("Failed to auto-suggest cmdline!\n");
					}
					return rv;
				}
			}
			/* Auto-complete the cmdline */
			if ((rv = autoCmdLine(pconn, CLISRV_AUTO_COMPLETE)) < 0) {
				u2up_log_error("Failed to auto-complete cmdline!\n");
			}
			return rv;
		}

		if (pconn->rcv[pconn->rcvlen - 1] == '\n') {
			pconn->rcv[pconn->rcvlen - 1] = '\0';
			pconn->rcvlen--;
			/* Execute the cmdline */
			if ((rv = execCmdLine(pconn)) < 0) {
				u2up_log_error("Failed to execute the cmdline!\n");
			}
			return rv;
		} else {
			/*message incomplete*/
			rv = 0;
		}
	} else {
		/*message empty*/
		rv = 0;
	}

	return rv;
}

static int parseReceivedData(clisrv_pconn_struct *pconn, char *data, int datasz /*data size including '\0', if received*/)
{
	char *tmp;
	u2up_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		u2up_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (data == NULL) {
		u2up_log_error("Invalid argument data=%p\n", data);
		return -1;
	}

	/* compare data size (datasz) and string length to check, if '\0' received */
	if (datasz != (strlen(data) + 1)) {
		u2up_log_error("Invalid argument datasz=%d (does not match string size)\n", datasz);
		return -1;
	}

	if ((tmp = (char *)reallocarray(pconn->rcv, datasz, sizeof(char))) == NULL) {
		u2up_log_system_error("realocarray() - rcv\n");
		abort();
	}
	pconn->rcv = tmp;
	memcpy(tmp, data, datasz);
	pconn->rcvlen = datasz - 1;

	if ((tmp = (char *)reallocarray(pconn->snd, CLISRV_MAX_MSGSZ, sizeof(char))) == NULL) {
		u2up_log_system_error("realocarray() - snd\n");
		abort();
	}
	pconn->snd = tmp;
	tmp[0] = '\0';
	pconn->sndsz = 1;

	return parseCmdLine(pconn);
}

#endif /*U2UP_CLI_FILE_u2up_clisrv_h*/

