/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>
Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"
#include <time.h>
#include "njet_iot_internal.h"

static time_t last_keepalive_check = 0;

/* FIXME - this is the prototype for the future tree/trie based keepalive check implementation. */

int keepalive__add(struct mosq_iot *context)
{
	UNUSED(context);

	return MOSQ_ERR_SUCCESS;
}

void keepalive__check(void)
{
	struct mosq_iot *context, *ctxt_tmp;

	if (last_keepalive_check + 5 < db.now_s)
	{
		last_keepalive_check = db.now_s;

		/* FIXME - this needs replacing with something more efficient */
		HASH_ITER(hh_sock, db.contexts_by_sock, context, ctxt_tmp)
		{
			if (context->sock != INVALID_SOCKET)
			{
				/* Local bridges never time out in this fashion. */
				if (!(context->keepalive) || context->bridge || db.now_s - context->last_msg_in <= (time_t)(context->keepalive) * 3 / 2)
				{
				}
				else
				{
					/* Client has exceeded keepalive*1.5 */
					do_disconnect(context, MOSQ_ERR_KEEPALIVE);
				}
			}
		}
	}
}

int keepalive__remove(struct mosq_iot *context)
{
	UNUSED(context);

	return MOSQ_ERR_SUCCESS;
}

void keepalive__remove_all(void)
{
}

int keepalive__update(struct mosq_iot *context)
{
	context->last_msg_in = db.now_s;
	return MOSQ_ERR_SUCCESS;
}
