/*
 * Copyright (c) 2017 Nikolay Marchuk <marchuk.nikolay.a@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include "filter.h"

#define DECL_FILTER_ACTION(name)					\
extern void								\
apply_ ## name(struct tcb *, void *)					\
/* End of DECL_FILTER_ACTION definition. */

DECL_FILTER_ACTION(trace);
DECL_FILTER_ACTION(inject);
DECL_FILTER_ACTION(fault);
DECL_FILTER_ACTION(read);
DECL_FILTER_ACTION(write);
DECL_FILTER_ACTION(raw);
DECL_FILTER_ACTION(abbrev);
DECL_FILTER_ACTION(verbose);
#undef DECL_FILTER_ACTION

extern bool is_traced(struct tcb *);
extern bool not_injected(struct tcb *);

#define DECL_FILTER_ACTION_PARSER(name)					\
extern void *								\
parse_ ## name(const char *);						\
extern void								\
free_ ## name(void *)							\
/* End of DECL_FILTER_ACTION_PARSER definition. */

DECL_FILTER_ACTION_PARSER(null);
DECL_FILTER_ACTION_PARSER(inject);
DECL_FILTER_ACTION_PARSER(fault);
#undef DECL_FILTER_ACTION_PARSER

#define FILTER_ACTION_TYPE(NAME, PRIORITY, PARSER, PREFILTER)		\
{#NAME, PRIORITY, parse_ ## PARSER, free_ ## PARSER, PREFILTER, apply_ ## NAME}

static const struct filter_action_type {
	const char *name;
	unsigned int priority;
	void * (*parse_args)(const char *);
	void (*free_priv_data)(void *);
	bool (*prefilter)(struct tcb *);
	void (*apply)(struct tcb *, void *);
} action_types[] = {
	FILTER_ACTION_TYPE(trace,	2,	null,	NULL),
	FILTER_ACTION_TYPE(inject,	2,	inject,	not_injected),
	FILTER_ACTION_TYPE(fault,	2,	fault,	not_injected),
	FILTER_ACTION_TYPE(read,	1,	null,	is_traced),
	FILTER_ACTION_TYPE(write,	1,	null,	is_traced),
	FILTER_ACTION_TYPE(raw,		1,	null,	is_traced),
	FILTER_ACTION_TYPE(abbrev,	1,	null,	is_traced),
	FILTER_ACTION_TYPE(verbose,	1,	null,	is_traced),
};
#undef FILTER_ACTION_TYPE

struct filter_action {
	/* Used to correct order of actions with same priority. */
	unsigned int id;
	const struct filter_action_type *type;
	struct bool_expression *expr;
	unsigned int nfilters;
	struct filter *filters;
	void *_priv_data;
};

static struct filter_action *filter_actions;
static unsigned int nfilter_actions;

static bool *variables_buf;

/* Compares actions priority. If actions have same priority, uses LIFO order */
static int
compare_action_priority(const void *a, const void *b)
{
	const struct filter_action *action_a = a;
	const struct filter_action *action_b = b;
	unsigned int priority_a = action_a->type->priority;
	unsigned int priority_b = action_b->type->priority;

	if (priority_a != priority_b) {
		return (priority_a > priority_b) ? -1 : 1;
	} else {
		return (action_a->id > action_b->id) ? -1 : 1;
	}
}

void
filtering_parsing_finish(void)
{
	unsigned int maxfilters = 0;
	unsigned int i;

	/* Sort actions by priority */
	qsort(filter_actions, nfilter_actions, sizeof(struct filter_action),
	      &compare_action_priority);

	/* Allocate variables_buf sufficient for any action */
	for (i = 0; i < nfilter_actions; ++i) {
		if (filter_actions[i].nfilters > maxfilters)
			maxfilters = filter_actions[i].nfilters;
	}
	variables_buf = xcalloc(maxfilters, sizeof(bool));
}

static const struct filter_action_type *
lookup_filter_action_type(const char *str)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(action_types); ++i) {
		if (!strcmp(action_types[i].name, str))
			return &action_types[i];
	}
	return NULL;
}

static struct filter_action *
add_action(const struct filter_action_type *type)
{
	struct filter_action *action;

	filter_actions = xreallocarray(filter_actions, ++nfilter_actions,
				       sizeof(struct filter_action));
	action = &filter_actions[nfilter_actions - 1];
	memset(action, 0, sizeof(*action));
	action->id = nfilter_actions - 1;
	action->type = type;
	action->expr = create_expression();
	return action;
}

struct filter_action *
find_or_add_action(const char *name)
{
	const struct filter_action_type *type = lookup_filter_action_type(name);
	unsigned int i;

	if (!type)
		error_msg_and_die("invalid filter action '%s'", name);
	/* If action takes arguments, add new action */
	if (type->parse_args != &parse_null)
		return add_action(type);

	for (i = 0; i < nfilter_actions; ++i) {
		if (filter_actions[i].type == type)
			return &filter_actions[i];
	}
	return add_action(type);
}

static void
run_filter_action(struct tcb *tcp, struct filter_action *action)
{
	if (action->type->prefilter && !action->type->prefilter(tcp))
		return;
	run_filters(tcp, action->filters, action->nfilters, variables_buf);
	if (run_expression(action->expr, variables_buf, action->nfilters))
		action->type->apply(tcp, action->_priv_data);
}

struct filter *
create_filter(struct filter_action *action, const char *name)
{
	return add_filter_to_array(&action->filters, &action->nfilters, name);
}

void
set_qualify_mode(struct filter_action *action)
{
	set_filters_qualify_mode(&action->filters, &action->nfilters);
	set_expression_qualify_mode(action->expr);
}

void
filter_syscall(struct tcb *tcp)
{
	unsigned int i;

	for (i = 0; i < nfilter_actions; ++i)
		run_filter_action(tcp, &filter_actions[i]);
}

void *
get_filter_action_priv_data(struct filter_action *action)
{
	return action ? action->_priv_data : NULL;
}

void
set_filter_action_priv_data(struct filter_action *action, void *_priv_data)
{
	if (action)
		action->_priv_data = _priv_data;
}