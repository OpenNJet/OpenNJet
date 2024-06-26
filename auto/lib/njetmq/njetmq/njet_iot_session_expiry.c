/*
Copyright (c) 2019-2020 Roger Light <roger@atchoo.org>
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

#include <math.h>
#include <stdio.h>
#include <utlist.h>

#include "njet_iot_internal.h"
#include "memory_mosq.h"
#include "sys_tree.h"
#include "time_mosq.h"

static struct iot_session_expiry_list *expiry_list = NULL;
static time_t last_check = 0;

static int session_expiry__cmp(struct iot_session_expiry_list *i1, struct iot_session_expiry_list *i2)
{
	if (i1->context->session_expiry_time == i2->context->session_expiry_time)
	{
		return 0;
	}
	else if (i1->context->session_expiry_time > i2->context->session_expiry_time)
	{
		return 1;
	}
	else
	{
		return -1;
	}
}

int session_expiry__add(struct mosq_iot *context)
{
	struct iot_session_expiry_list *item;

	if (db.config->persistent_client_expiration == 0)
	{
		if (context->session_expiry_interval == UINT32_MAX)
		{
			/* There isn't a global expiry set, and the client has asked to
			 * never expire, so we don't add it to the list. */
			return MOSQ_ERR_SUCCESS;
		}
	}

	item = mosquitto__calloc(1, sizeof(struct iot_session_expiry_list));
	if (!item)
		return MOSQ_ERR_NOMEM;

	item->context = context;
	item->context->session_expiry_time = db.now_real_s;

	if (db.config->persistent_client_expiration == 0)
	{
		/* No global expiry, so use the client expiration interval */
		item->context->session_expiry_time += item->context->session_expiry_interval;
	}
	else
	{
		/* We have a global expiry interval */
		if (db.config->persistent_client_expiration < item->context->session_expiry_interval)
		{
			/* The client expiry is longer than the global expiry, so use the global */
			item->context->session_expiry_time += db.config->persistent_client_expiration;
		}
		else
		{
			/* The global expiry is longer than the client expiry, so use the client */
			item->context->session_expiry_time += item->context->session_expiry_interval;
		}
	}
	context->expiry_list_item = item;

	DL_INSERT_INORDER(expiry_list, item, session_expiry__cmp);

	return MOSQ_ERR_SUCCESS;
}

void session_expiry__remove(struct mosq_iot *context)
{
	if (context->expiry_list_item)
	{
		DL_DELETE(expiry_list, context->expiry_list_item);
		mosquitto__free(context->expiry_list_item);
		context->expiry_list_item = NULL;
	}
}

/* Call on broker shutdown only */
void session_expiry__remove_all(void)
{
	struct iot_session_expiry_list *item, *tmp;
	struct mosq_iot *context;

	DL_FOREACH_SAFE(expiry_list, item, tmp)
	{
		context = item->context;
		session_expiry__remove(context);
		context->session_expiry_interval = 0;
		context->will_delay_interval = 0;
		iot_will_delay__remove(context);
		context__disconnect(context);
	}
}

void session_expiry__check(void)
{
	struct iot_session_expiry_list *item, *tmp;
	struct mosq_iot *context;

	if (db.now_real_s <= last_check)
		return;

	last_check = db.now_real_s;

	DL_FOREACH_SAFE(expiry_list, item, tmp)
	{
		if (item->context->session_expiry_time < db.now_real_s)
		{

			context = item->context;
			session_expiry__remove(context);

			if (context->id)
			{
				iot_log__printf(NULL, MOSQ_LOG_NOTICE, "Expiring client %s due to timeout.", context->id);
			}
			G_CLIENTS_EXPIRED_INC();

			/* Session has now expired, so clear interval */
			context->session_expiry_interval = 0;
			/* Session has expired, so will delay should be cleared. */
			context->will_delay_interval = 0;
			iot_will_delay__remove(context);
			context__send_will(context);
			context__add_to_disused(context);
		}
		else
		{
			return;
		}
	}
}
