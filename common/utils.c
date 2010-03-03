/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 Red Hat, Inc.
 */

#include <string.h>
#include <nm-setting-8021x.h>
#include "utils.h"

gboolean
is_pkcs12 (const char *filepath)
{
	NMSetting8021xCKType ck_type = NM_SETTING_802_1X_CK_TYPE_UNKNOWN;
	NMSetting8021x *s_8021x;

	if (!filepath || !strlen (filepath))
		return FALSE;

	if (!g_file_test (filepath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
		return FALSE;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_return_val_if_fail (s_8021x != NULL, FALSE);

	nm_setting_802_1x_set_private_key_from_file (s_8021x,
	                                             filepath,
	                                             NULL,
	                                             &ck_type,
	                                             NULL);
	g_object_unref (s_8021x);

	return (ck_type == NM_SETTING_802_1X_CK_TYPE_PKCS12);
}

#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"

/** Checks if a key is encrypted
 * The key file is read and it is checked if it contains a line reading
 * Proc-Type: 4,ENCRYPTED
 * This is defined in RFC 1421 (PEM)
 * @param filename the path to the file
 * @return returns true if the key is encrypted, false otherwise
 */
gboolean
is_encrypted_pem (const char *filename)
{
	GIOChannel *pem_chan;
	char *str = NULL;
	gboolean encrypted = FALSE;

	if (!filename || !strlen (filename))
		return FALSE;

	pem_chan = g_io_channel_new_file (filename, "r", NULL);
	if (!pem_chan)
		return FALSE;

	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (strncmp (str, PROC_TYPE_TAG, strlen (PROC_TYPE_TAG)) == 0) {
			encrypted = TRUE;
			break;
		}
		g_free (str);
	}

	g_io_channel_shutdown (pem_chan, FALSE, NULL);
	g_io_channel_unref (pem_chan);
	return encrypted;
}
