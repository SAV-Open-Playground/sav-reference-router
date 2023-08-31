/*
 *	BIRD Internet Routing Daemon -- CLI Commands Which Don't Fit Anywhere Else
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

struct sym_show_data {
	int	type;	/* Symbols type to show */
	struct symbol	*sym;
};

struct f_inst;

void cmd_show_status(void);
void cmd_show_symbols(struct sym_show_data *sym);
void cmd_show_memory(void);
void call_agent(void);
void test_send(void);
void call_log(void);
struct f_line;
void cmd_eval(const struct f_line *expr);
