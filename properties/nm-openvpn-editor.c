/*
 * network-manager-openvpn - OpenVPN integration with NetworkManager
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
 * Based on work by David Zeuthen, <davidz@redhat.com>
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 Tambet Ingo, <tambet@gmail.com>
 * Copyright (C) 2008 - 2010 Dan Williams, <dcbw@redhat.com>
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-openvpn-editor.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"

#if !GTK_CHECK_VERSION(4,0,0)
#define gtk_editable_set_text(editable,text)		gtk_entry_set_text(GTK_ENTRY(editable), (text))
#define gtk_editable_get_text(editable)			gtk_entry_get_text(GTK_ENTRY(editable))
#define gtk_window_destroy(window)			gtk_widget_destroy(GTK_WIDGET (window))
#define gtk_widget_get_root(widget)			gtk_widget_get_toplevel(widget)
#define gtk_check_button_get_active(button)		gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button))
#define gtk_check_button_set_active(button, active)	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), active)
#define gtk_window_set_hide_on_close(window, hide)						\
	G_STMT_START {										\
		G_STATIC_ASSERT(hide);								\
		g_signal_connect_swapped (G_OBJECT (window), "delete-event",			\
					  G_CALLBACK (gtk_widget_hide_on_delete), window);	\
	} G_STMT_END

typedef void GtkRoot;
#endif

/*****************************************************************************/

#define BLOCK_HANDLER_ID "block-handler-id"

/*****************************************************************************/

typedef void (*ChangedCallback) (GtkWidget *widget, gpointer user_data);

static GtkFileFilter *sk_file_chooser_filter_new (void);

/*****************************************************************************/

/* From gnome-control-center/panels/network/connection-editor/ui-helpers.c */

static void
widget_set_error (GtkWidget *widget)
{
	g_return_if_fail (GTK_IS_WIDGET (widget));

	gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
}

static void
widget_unset_error (GtkWidget *widget)
{
	g_return_if_fail (GTK_IS_WIDGET (widget));

	gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
}

/*****************************************************************************/

static void
chooser_button_update_file (GtkLabel *label, GFile *file)
{
	char *basename = NULL;

	if (file)
		basename = g_file_get_basename (file);
	if (basename) {
		gtk_label_set_label (label, basename);
		g_free (basename);
	} else {
		gtk_label_set_label (label, _("(None)"));
	}
}

static void
chooser_button_update (GtkLabel *label, GtkFileChooser *chooser)
{
	GFile *file;

	file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (chooser));
	chooser_button_update_file (label, file);
	g_clear_object (&file);
}

static void
chooser_response (GtkDialog *chooser, gint response_id, gpointer user_data)
{
	GtkLabel *label = GTK_LABEL(user_data);
	GFile *file;

	if (response_id == GTK_RESPONSE_ACCEPT)
		chooser_button_update (label, GTK_FILE_CHOOSER (chooser));

	/* The current file is freed when the file chooser widget is unmapped
	* (see gtk_file_chooser_widget_unmap function).
	* So we need to restore it after hiding the dialog. */

	file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (chooser));

	gtk_widget_hide (GTK_WIDGET (chooser));

	gtk_file_chooser_set_file (GTK_FILE_CHOOSER (chooser), file, NULL);
	g_clear_object (&file);

}

static void
tls_ca_changed_cb (NMACertChooser *this, gpointer user_data)
{
	NMACertChooser *other = user_data;
	NMSetting8021xCKScheme scheme;
	gs_free char *ca_cert = NULL;
	gs_free char *client_cert = NULL;
	gs_free char *client_key = NULL;

	client_key = nma_cert_chooser_get_key (other, &scheme);
	client_cert = nma_cert_chooser_get_cert (other, &scheme);
	ca_cert = nma_cert_chooser_get_cert (this, &scheme);

	/* OpenVPN allows --pkcs12 with --ca, but if the provided CA is a PKCS#12 file,
	 * we have to also set the cert/key to the same file - since OpenVPN does not
	 * allow mixing of --pkcs12 and --cert/--key. */
	if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
	    && is_pkcs12 (ca_cert)) {
		nma_cert_chooser_set_cert (other, ca_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		nma_cert_chooser_set_key (other, ca_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
	}
}

static void
tls_cert_changed_cb (NMACertChooser *this, gpointer user_data)
{
	NMACertChooser *other = user_data;
	NMSetting8021xCKScheme scheme;
	gs_free char *ca_cert = NULL;
	gs_free char *client_cert = NULL;
	gs_free char *client_key = NULL;

	ca_cert = nma_cert_chooser_get_cert (other, &scheme);
	client_key = nma_cert_chooser_get_key (this, &scheme);
	client_cert = nma_cert_chooser_get_cert (this, &scheme);

	/* OpenVPN does not allow a combination of --cert/--key and --pkcs12; however,
	 * it does allow --pkcs12 with --ca. */
	if (client_cert && is_pkcs12 (client_cert)) {
		if (!ca_cert)
			nma_cert_chooser_set_cert (other, client_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
		if (   ca_cert
		    && is_pkcs12 (ca_cert)
		    && !nm_streq (client_cert, ca_cert))
			nma_cert_chooser_set_cert (other, client_cert, NM_SETTING_802_1X_CK_SCHEME_PATH);
	} else if (client_cert && !is_pkcs12 (client_cert)) {
		if (client_key && is_pkcs12 (client_key)) {
			nma_cert_chooser_set_key (this, NULL, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);
			nma_cert_chooser_set_cert_password (this, "");
		}
		if (ca_cert && is_pkcs12 (ca_cert))
			nma_cert_chooser_set_cert (other, NULL, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN);
	}
}

static void
tls_setup (GtkBuilder *builder,
           NMSettingVpn *s_vpn,
           const char *prefix,
           NMACertChooser *ca_chooser,
           ChangedCallback changed_cb,
           gpointer user_data)
{
	NMACertChooser *cert;
	const char *value;
	char namebuf[150];

	nm_sprintf_buf (namebuf, "%s_user_cert", prefix);
	cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, namebuf));

	nma_cert_chooser_add_to_size_group (cert, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));
	g_signal_connect (G_OBJECT (cert), "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
		if (value && *value)
			nma_cert_chooser_set_cert (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);

		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		if (value && *value)
			nma_cert_chooser_set_key (cert, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS);
		if (value)
			nma_cert_chooser_set_key_password (cert, value);
	}

	nma_cert_chooser_setup_key_password_storage (cert, NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                                             (NMSetting *) s_vpn,
	                                             NM_OPENVPN_KEY_CERTPASS, TRUE, FALSE);

	/* Link choosers to the PKCS#12 changer callbacks */
	g_signal_connect_object (ca_chooser, "changed", G_CALLBACK (tls_ca_changed_cb), cert, 0);
	g_signal_connect_object (cert, "changed", G_CALLBACK (tls_cert_changed_cb), ca_chooser, 0);
}

static void
pw_setup (GtkBuilder *builder,
          NMSettingVpn *s_vpn,
          const char *prefix,
          ChangedCallback changed_cb,
          gpointer user_data)
{
	GtkWidget *widget;
	const char *value;
	char namebuf[150];

	nm_sprintf_buf (namebuf, "%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, namebuf));

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME);
		if (value && *value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);

	/* Fill in the user password */
	nm_sprintf_buf (namebuf, "%s_password_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, namebuf));
	g_signal_connect (widget, "changed", G_CALLBACK (changed_cb), user_data);

	if (s_vpn) {
		value = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}

	nma_utils_setup_password_storage (widget, NM_SETTING_SECRET_FLAG_AGENT_OWNED,
	                                  (NMSetting *) s_vpn, NM_OPENVPN_KEY_PASSWORD,
	                                  TRUE, FALSE);
}

static void
tls_pw_init_auth_widget (GtkBuilder *builder,
                         NMSettingVpn *s_vpn,
                         const char *contype,
                         const char *prefix,
                         ChangedCallback changed_cb,
                         gpointer user_data)
{
	NMACertChooser *ca;
	const char *value;
	char namebuf[150];
	gboolean tls = FALSE, pw = FALSE;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);
	g_return_if_fail (prefix != NULL);

	nm_sprintf_buf (namebuf, "%s_ca_cert", prefix);
	ca = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, namebuf));
	nma_cert_chooser_add_to_size_group (ca, GTK_SIZE_GROUP (gtk_builder_get_object (builder, "labels")));

	/* Three major connection types here: TLS-only, PW-only, and TLS + PW */
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		tls = TRUE;
	if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD) || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		pw = TRUE;

	g_signal_connect (ca, "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (value && *value)
			nma_cert_chooser_set_cert (ca, value, NM_SETTING_802_1X_CK_SCHEME_PATH);
	}

	/* Set up the rest of the options */
	if (tls)
		tls_setup (builder, s_vpn, prefix, ca, changed_cb, user_data);
	if (pw)
		pw_setup (builder, s_vpn, prefix, changed_cb, user_data);
}

static void
sk_key_chooser_show (GtkWidget *parent, GtkWidget *widget)
{
	GtkRoot *root;

	root = gtk_widget_get_root (parent);
	g_return_if_fail (GTK_IS_WINDOW(root));

	gtk_window_set_transient_for (GTK_WINDOW (widget), GTK_WINDOW (root));
	gtk_widget_show (widget);
}

#define SK_DIR_COL_NAME 0
#define SK_DIR_COL_NUM  1

static void
sk_init_auth_widget (GtkBuilder *builder,
                     NMSettingVpn *s_vpn,
                     ChangedCallback changed_cb,
                     gpointer user_data)
{
	GtkWidget *widget;
	GtkLabel *label;
	const char *value = NULL;
	GFile *file = NULL;
	GtkListStore *store;
	GtkTreeIter iter;
	gint active = -1;
	gint direction;
	GtkFileFilter *filter;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (changed_cb != NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
	label = GTK_LABEL (gtk_builder_get_object (builder, "sk_key_chooser_label"));
	gtk_window_set_hide_on_close (GTK_WINDOW(widget), TRUE);
	g_signal_connect (gtk_builder_get_object (builder, "sk_key_chooser_button"),
	                  "clicked", G_CALLBACK (sk_key_chooser_show), widget);

	filter = sk_file_chooser_filter_new ();
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget), filter);
#if !GTK_CHECK_VERSION(4,0,0)
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
#endif
	g_signal_connect (G_OBJECT (widget), "response", G_CALLBACK (chooser_response), label);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (value && *value) {
			file = g_file_new_for_path (value);
			gtk_file_chooser_set_file (GTK_FILE_CHOOSER (widget), file, NULL);
		}
	}
	chooser_button_update_file (label, file);
	g_clear_object (&file);



	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
		direction = _nm_utils_ascii_str_to_int64 (value, 10, 0, 1, -1);
	} else
		direction = -1;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, _("None"), SK_DIR_COL_NUM, -1, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "0", SK_DIR_COL_NUM, 0, -1);
	if (direction == 0)
		active = 1;

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, SK_DIR_COL_NAME, "1", SK_DIR_COL_NUM, 1, -1);
	if (direction == 1)
		active = 2;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
		if (value && *value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (changed_cb), user_data);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
		if (value && *value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
}

static gboolean
validate_cert_chooser (GtkBuilder *builder, const char *name, GError **error)
{
	NMACertChooser *chooser;

	chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, name));
	return nma_cert_chooser_validate (chooser, error);
}

static gboolean
validate_tls (GtkBuilder *builder, const char *prefix, GError **error)
{
	gboolean valid, encrypted = FALSE;
	NMACertChooser *user_cert;
	NMSettingSecretFlags pw_flags;
	gboolean secrets_required = TRUE;
	NMSetting8021xCKScheme scheme;
	GError *local = NULL;
	char *tmp;
	char namebuf[150];

	nm_sprintf_buf (namebuf, "%s_ca_cert", prefix);
	valid = validate_cert_chooser (builder, namebuf, &local);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             "%s: %s", NM_OPENVPN_KEY_CA, local->message);
		g_error_free (local);
		return FALSE;
	}

	nm_sprintf_buf (namebuf, "%s_user_cert", prefix);
	user_cert = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, namebuf));
	valid = validate_cert_chooser (builder, namebuf, &local);
	if (!valid) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             "%s: %s", NM_OPENVPN_KEY_CERT, local->message);
		g_error_free (local);
		return FALSE;
	}

	/* Encrypted certificates require a password */
	tmp = nma_cert_chooser_get_cert (user_cert, &scheme);
	encrypted = is_encrypted (tmp);
	g_free (tmp);

	pw_flags = nma_cert_chooser_get_key_password_flags (user_cert);
	if (   pw_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED
	    || pw_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		secrets_required = FALSE;

	if (encrypted && secrets_required) {
		if (!nma_cert_chooser_get_key_password (user_cert)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_CERTPASS);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
auth_widget_check_validity (GtkBuilder *builder, const char *contype, GError **error)
{
	GtkWidget *widget;
	const char *str;
	GFile *file;
	GError *local = NULL;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		if (!validate_tls (builder, "tls", error))
			return FALSE;
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		if (!validate_tls (builder, "pw_tls", error))
			return FALSE;
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		if (!validate_cert_chooser (builder, "pw_ca_cert", &local)) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             "%s: %s", NM_OPENVPN_KEY_CA, local->message);
			g_error_free (local);
			return FALSE;
		}
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
		if (!file) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_STATIC_KEY);
			return FALSE;
		}
		g_object_unref (file);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (!str || !*str) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_LOCAL_IP);
			return FALSE;
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (!str || !*str) {
			g_set_error (error,
			             NMV_EDITOR_PLUGIN_ERROR,
			             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
			             NM_OPENVPN_KEY_REMOTE_IP);
			return FALSE;
		}
	} else
		g_return_val_if_reached (FALSE);

	return TRUE;
}

static void
update_from_cert_chooser (GtkBuilder *builder,
                          const char *cert_prop,
                          const char *key_prop,
                          const char *key_pass_prop,
                          const char *prefix,
                          const char *widget_name,
                          NMSettingVpn *s_vpn)
{
	NMSetting8021xCKScheme scheme;
	NMACertChooser *cert_chooser;
	NMSettingSecretFlags pw_flags;
	char *tmp;
	char namebuf[150];
	const char *password;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (cert_prop != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (widget_name != NULL);
	g_return_if_fail (s_vpn != NULL);

	nm_sprintf_buf (namebuf, "%s_%s", prefix, widget_name);
	cert_chooser = NMA_CERT_CHOOSER (gtk_builder_get_object (builder, namebuf));

	tmp = nma_cert_chooser_get_cert (cert_chooser, &scheme);
	if (tmp && *tmp)
		nm_setting_vpn_add_data_item (s_vpn, cert_prop, tmp);
	g_free (tmp);

	if (key_prop) {
		g_return_if_fail (key_pass_prop != NULL);

		tmp = nma_cert_chooser_get_key (cert_chooser, &scheme);
		if (tmp && *tmp)
			nm_setting_vpn_add_data_item (s_vpn, key_prop, tmp);
		g_free (tmp);

		password = nma_cert_chooser_get_key_password (cert_chooser);
		if (password && *password)
			nm_setting_vpn_add_secret (s_vpn, key_pass_prop, password);

		pw_flags = nma_cert_chooser_get_key_password_flags (cert_chooser);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn), key_pass_prop, pw_flags, NULL);
	}
}

static void
update_tls (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	update_from_cert_chooser (builder,
	                          NM_OPENVPN_KEY_CA,
	                          NULL,
	                          NULL,
	                          prefix, "ca_cert", s_vpn);

	update_from_cert_chooser (builder,
	                          NM_OPENVPN_KEY_CERT,
	                          NM_OPENVPN_KEY_KEY,
	                          NM_OPENVPN_KEY_CERTPASS,
	                          prefix, "user_cert", s_vpn);
}

static void
update_pw (GtkBuilder *builder, const char *prefix, NMSettingVpn *s_vpn)
{
	GtkWidget *widget;
	NMSettingSecretFlags pw_flags;
	char namebuf[150];
	const char *str;

	g_return_if_fail (builder != NULL);
	g_return_if_fail (prefix != NULL);
	g_return_if_fail (s_vpn != NULL);

	nm_sprintf_buf (namebuf, "%s_username_entry", prefix);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, namebuf));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME, str);

	nm_sprintf_buf (namebuf, "%s_password_entry", prefix);
	widget = (GtkWidget *) gtk_builder_get_object (builder, namebuf);
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && *str)
		nm_setting_vpn_add_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD, str);
	pw_flags = nma_utils_menu_to_secret_flags (widget);
	nm_setting_set_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, pw_flags, NULL);
}

static gboolean
auth_widget_update_connection (GtkBuilder *builder,
                               const char *contype,
                               NMSettingVpn *s_vpn)
{
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkWidget *widget;
	const char *str;
	char *filename;
	GFile *file;

	if (!strcmp (contype, NM_OPENVPN_CONTYPE_TLS)) {
		update_tls (builder, "tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		update_from_cert_chooser (builder, NM_OPENVPN_KEY_CA, NULL, NULL,
		                          "pw", "ca_cert", s_vpn);
		update_pw (builder, "pw", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		update_tls (builder, "pw_tls", s_vpn);
		update_pw (builder, "pw_tls", s_vpn);
	} else if (!strcmp (contype, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		/* Update static key */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_key_chooser"));
		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
		if (file)
			filename = g_file_get_path (file);
		else
			filename = NULL;
		if (filename && filename[0])
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY, filename);
		g_free (filename);
		g_clear_object (&file);

		/* Update direction */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_direction_combo"));
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
		if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
			int direction;

			gtk_tree_model_get (model, &iter, SK_DIR_COL_NUM, &direction, -1);
			if (direction > -1) {
				char tmp[30];

				nm_sprintf_buf (tmp, "%d", direction);
				nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, tmp);
			}
		}

		/* Update local address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_local_address_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP, str);

		/* Update remote address */
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "sk_remote_address_entry"));
		str = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (str && *str)
			nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP, str);
	} else
		g_return_val_if_reached (FALSE);

	return TRUE;
}

#if GTK_CHECK_VERSION(4,0,0)
static void
sk_add_default_filter (GtkFileFilter *filter)
{
	gtk_file_filter_add_pattern (filter, "*.key");
}
#else
static const char *
find_tag (const char *tag, const char *buf, gsize len)
{
	gsize i, taglen;

	taglen = strlen (tag);
	if (len < taglen)
		return NULL;

	for (i = 0; i < len - taglen + 1; i++) {
		if (memcmp (buf + i, tag, taglen) == 0)
			return buf + i;
	}
	return NULL;
}

static const char *sk_key_begin = "-----BEGIN OpenVPN Static key V1-----";

static gboolean
sk_default_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	int fd;
	unsigned char buffer[1024];
	ssize_t bytes_read;
	gboolean show = FALSE;
	char *p;
	char *ext;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (!p)
		return FALSE;

	ext = g_ascii_strdown (p, -1);
	if (!ext)
		return FALSE;
	if (!g_str_has_suffix (ext, ".key")) {
		g_free (ext);
		return FALSE;
	}
	g_free (ext);

	fd = open (filter_info->filename, O_RDONLY);
	if (fd < 0)
		return FALSE;

	bytes_read = read (fd, buffer, sizeof (buffer) - 1);
	if (bytes_read < 400)  /* needs to be lower? */
		goto out;
	buffer[bytes_read] = '\0';

	/* Check for PEM signatures */
	if (find_tag (sk_key_begin, (const char *) buffer, bytes_read)) {
		show = TRUE;
		goto out;
	}

out:
	close (fd);
	return show;
}

static void
sk_add_default_filter (GtkFileFilter *filter)
{
	gtk_file_filter_add_custom (filter, GTK_FILE_FILTER_FILENAME, sk_default_filter, NULL, NULL);
}
#endif

static GtkFileFilter *
sk_file_chooser_filter_new (void)
{
	GtkFileFilter *filter;

	filter = gtk_file_filter_new ();
	sk_add_default_filter (filter);
	gtk_file_filter_set_name (filter, _("OpenVPN Static Keys (*.key)"));
	return filter;
}

static const char *const advanced_keys[] = {
	NM_OPENVPN_KEY_ALLOW_PULL_FQDN,
	NM_OPENVPN_KEY_AUTH,
	NM_OPENVPN_KEY_CIPHER,
	NM_OPENVPN_KEY_COMPRESS,
	NM_OPENVPN_KEY_COMP_LZO,
	NM_OPENVPN_KEY_CONNECT_TIMEOUT,
	NM_OPENVPN_KEY_CRL_VERIFY_DIR,
	NM_OPENVPN_KEY_CRL_VERIFY_FILE,
	NM_OPENVPN_KEY_DEV,
	NM_OPENVPN_KEY_DEV_TYPE,
	NM_OPENVPN_KEY_EXTRA_CERTS,
	NM_OPENVPN_KEY_FLOAT,
	NM_OPENVPN_KEY_FRAGMENT_SIZE,
	NM_OPENVPN_KEY_HTTP_PROXY_USERNAME,
	NM_OPENVPN_KEY_KEYSIZE,
	NM_OPENVPN_KEY_MAX_ROUTES,
	NM_OPENVPN_KEY_MSSFIX,
	NM_OPENVPN_KEY_MTU_DISC,
	NM_OPENVPN_KEY_NCP_DISABLE,
	NM_OPENVPN_KEY_NS_CERT_TYPE,
	NM_OPENVPN_KEY_PING,
	NM_OPENVPN_KEY_PING_EXIT,
	NM_OPENVPN_KEY_PING_RESTART,
	NM_OPENVPN_KEY_PORT,
	NM_OPENVPN_KEY_PROTO_TCP,
	NM_OPENVPN_KEY_PROXY_PORT,
	NM_OPENVPN_KEY_PROXY_RETRY,
	NM_OPENVPN_KEY_PROXY_SERVER,
	NM_OPENVPN_KEY_PROXY_TYPE,
	NM_OPENVPN_KEY_PUSH_PEER_INFO,
	NM_OPENVPN_KEY_REMOTE_CERT_TLS,
	NM_OPENVPN_KEY_REMOTE_RANDOM,
	NM_OPENVPN_KEY_REMOTE_RANDOM_HOSTNAME,
	NM_OPENVPN_KEY_RENEG_SECONDS,
	NM_OPENVPN_KEY_TA,
	NM_OPENVPN_KEY_TAP_DEV,
	NM_OPENVPN_KEY_TA_DIR,
	NM_OPENVPN_KEY_TLS_CIPHER,
	NM_OPENVPN_KEY_TLS_CRYPT,
	NM_OPENVPN_KEY_TLS_CRYPT_V2,
	NM_OPENVPN_KEY_TLS_REMOTE,
	NM_OPENVPN_KEY_TLS_VERSION_MIN,
	NM_OPENVPN_KEY_TLS_VERSION_MIN_OR_HIGHEST,
	NM_OPENVPN_KEY_TLS_VERSION_MAX,
	NM_OPENVPN_KEY_TUNNEL_MTU,
	NM_OPENVPN_KEY_TUN_IPV6,
	NM_OPENVPN_KEY_VERIFY_X509_NAME,
};

static void
copy_values (const char *key, const char *value, gpointer user_data)
{
	GHashTable *hash = (GHashTable *) user_data;
	gssize idx;

	idx = nm_utils_strv_find_first ((char **) advanced_keys, G_N_ELEMENTS (advanced_keys), key);
	if (idx >= 0)
		g_hash_table_insert (hash, (gpointer) advanced_keys[idx], g_strdup (value));
}

static GHashTable *
advanced_dialog_new_hash_from_connection (NMConnection *connection)
{
	GHashTable *hash;
	NMSettingVpn *s_vpn;
	const char *secret, *flags;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	s_vpn = nm_connection_get_setting_vpn (connection);
	nm_setting_vpn_foreach_data_item (s_vpn, copy_values, hash);

	/* HTTP Proxy password is special */
	secret = nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
	if (secret) {
		g_hash_table_insert (hash,
		                     NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,
		                     g_strdup (secret));
	}
	flags = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD_FLAGS);
	if (flags) {
		g_hash_table_insert (hash,
		                     NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD_FLAGS,
		                     g_strdup (flags));
	}

	return hash;
}

static void
checkbox_toggled_update_widget_cb (GtkWidget *check, gpointer user_data)
{
	GtkWidget *widget = (GtkWidget*) user_data;

	gtk_widget_set_sensitive (widget, gtk_check_button_get_active (GTK_CHECK_BUTTON (check)));
}

static const char *
nm_find_openvpn (void)
{
	static const char *openvpn_binary_paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		NULL
	};
	const char  **openvpn_binary = openvpn_binary_paths;

	while (*openvpn_binary != NULL) {
		if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
			break;
		openvpn_binary++;
	}

	return *openvpn_binary;
}

#define TLS_CIPHER_COL_NAME 0
#define TLS_CIPHER_COL_DEFAULT 1

static void
populate_cipher_combo (GtkComboBox *box, const char *user_cipher)
{
	GtkListStore *store;
	GtkTreeIter iter;
	const char *openvpn_binary = NULL;
	gchar *tmp, **items, **item;
	gboolean user_added = FALSE;
	char *argv[3];
	GError *error = NULL;
	gboolean success, ignore_lines = TRUE;

	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary)
		return;

	argv[0] = (char *) openvpn_binary;
	argv[1] = "--show-ciphers";
	argv[2] = NULL;

	success = g_spawn_sync ("/", argv, NULL, 0, NULL, NULL, &tmp, NULL, NULL, &error);
	if (!success) {
		g_warning ("%s: couldn't determine ciphers: %s", __func__, error->message);
		g_error_free (error);
		return;
	}

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --cipher to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, _("Default"),
	                    TLS_CIPHER_COL_DEFAULT, TRUE, -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_CIPHER_COL_NAME, "none",
	                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
	if (g_strcmp0 (user_cipher, "none") == 0) {
		gtk_combo_box_set_active_iter (box, &iter);
		user_added = TRUE;
	}

	items = g_strsplit (tmp, "\n", 0);
	g_free (tmp);

	for (item = items; *item; item++) {
		char *space;

		/* Don't add anything until after the first blank line. Also,
		 * any blank line indicates the start of a comment, ended by
		 * another blank line. */
		if (!strlen (*item)) {
			ignore_lines = !ignore_lines;
			continue;
		}

		if (ignore_lines)
			continue;

		space = strchr (*item, ' ');
		if (space)
			*space = '\0';

		if (strcmp (*item, "none") == 0)
			continue;

		if (strlen (*item)) {
			gtk_list_store_append (store, &iter);
			gtk_list_store_set (store, &iter,
			                    TLS_CIPHER_COL_NAME, *item,
			                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
			if (!user_added && user_cipher && !g_ascii_strcasecmp (*item, user_cipher)) {
				gtk_combo_box_set_active_iter (box, &iter);
				user_added = TRUE;
			}
		}
	}

	/* Add the user-specified cipher if it exists wasn't found by openvpn */
	if (user_cipher && !user_added) {
		gtk_list_store_insert (store, &iter, 1);
		gtk_list_store_set (store, &iter,
		                    TLS_CIPHER_COL_NAME, user_cipher,
		                    TLS_CIPHER_COL_DEFAULT, FALSE, -1);
		gtk_combo_box_set_active_iter (box, &iter);
	} else if (!user_added) {
		gtk_combo_box_set_active (box, 0);
	}

	g_object_unref (G_OBJECT (store));
	g_strfreev (items);
}

#define HMACAUTH_COL_NAME 0
#define HMACAUTH_COL_VALUE 1

static void
populate_hmacauth_combo (GtkComboBox *box, const char *hmacauth)
{
	gs_unref_object GtkListStore *store = NULL;
	GtkTreeIter iter;
	gboolean active_initialized = FALSE;
	int i;
	static const struct {
		const char *name;
		const char *pretty_name;
	} items[] = {
		{ NM_OPENVPN_AUTH_NONE,      N_("None") },
		{ NM_OPENVPN_AUTH_RSA_MD4,   N_("RSA MD-4") },
		{ NM_OPENVPN_AUTH_MD5,       N_("MD-5") },
		{ NM_OPENVPN_AUTH_SHA1,      N_("SHA-1") },
		{ NM_OPENVPN_AUTH_SHA224,    N_("SHA-224") },
		{ NM_OPENVPN_AUTH_SHA256,    N_("SHA-256") },
		{ NM_OPENVPN_AUTH_SHA384,    N_("SHA-384") },
		{ NM_OPENVPN_AUTH_SHA512,    N_("SHA-512") },
		{ NM_OPENVPN_AUTH_RIPEMD160, N_("RIPEMD-160") },
	};

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_BOOLEAN);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	/* Add default option which won't pass --auth to openvpn */
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    HMACAUTH_COL_NAME, _("Default"),
	                    -1);

	for (i = 0; i < G_N_ELEMENTS (items); i++) {
		const char *name = items[i].name;

		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
		                    HMACAUTH_COL_NAME, _(items[i].pretty_name),
		                    HMACAUTH_COL_VALUE, name,
		                    -1);
		if (hmacauth && !g_ascii_strcasecmp (name, hmacauth)) {
			gtk_combo_box_set_active_iter (box, &iter);
			active_initialized = TRUE;
		}
	}

	if (!active_initialized) {
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter,
		                    HMACAUTH_COL_NAME, hmacauth,
		                    HMACAUTH_COL_VALUE, hmacauth,
		                    -1);
		gtk_combo_box_set_active_iter (box, &iter);
	}
}

#define TLS_REMOTE_MODE_NONE        "none"
#define TLS_REMOTE_MODE_SUBJECT     NM_OPENVPN_VERIFY_X509_NAME_TYPE_SUBJECT
#define TLS_REMOTE_MODE_NAME        NM_OPENVPN_VERIFY_X509_NAME_TYPE_NAME
#define TLS_REMOTE_MODE_NAME_PREFIX NM_OPENVPN_VERIFY_X509_NAME_TYPE_NAME_PREFIX
#define TLS_REMOTE_MODE_LEGACY      "legacy"

#define TLS_REMOTE_MODE_COL_NAME 0
#define TLS_REMOTE_MODE_COL_VALUE 1

static void
populate_tls_remote_mode_entry_combo (GtkEditable* entry, GtkComboBox *box,
                                      const char *tls_remote, const char *x509_name)
{
	GtkListStore *store;
	GtkTreeIter iter;
	const char *subject_name = NULL;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Don’t verify certificate identification"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NONE,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify whole subject exactly"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_SUBJECT,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify name exactly"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NAME,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify name by prefix"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_NAME_PREFIX,
	                    -1);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    TLS_REMOTE_MODE_COL_NAME, _("Verify subject partially (legacy mode, strongly discouraged)"),
	                    TLS_REMOTE_MODE_COL_VALUE, TLS_REMOTE_MODE_LEGACY,
	                    -1);

	if (x509_name && *x509_name) {
		if (g_str_has_prefix (x509_name, "name:"))
			gtk_combo_box_set_active (box, 2);
		else if (g_str_has_prefix (x509_name, "name-prefix:"))
			gtk_combo_box_set_active (box, 3);
		else
			gtk_combo_box_set_active (box, 1);

		subject_name = strchr (x509_name, ':');
		if (subject_name)
			subject_name++;
		else
			subject_name = x509_name;
	} else if (tls_remote && *tls_remote) {
		gtk_combo_box_set_active (box, 4);

		subject_name = tls_remote;
	} else {
		gtk_combo_box_set_active (box, 0);

		subject_name = "";
	}

	gtk_editable_set_text (entry, subject_name);

	g_object_unref (store);
}

static void
tls_remote_changed (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *entry, *combo, *ok_button;
	GtkTreeIter iter;
	gboolean entry_enabled = TRUE, entry_has_error = FALSE;
	gboolean legacy_tls_remote = FALSE;

	entry     = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
	combo     = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
		gs_free char *tls_remote_mode = NULL;
		GtkTreeModel *combo_model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

		gtk_tree_model_get (combo_model, &iter, TLS_REMOTE_MODE_COL_VALUE, &tls_remote_mode, -1);

		/* If a mode of 'none' is selected, disable the subject entry control.
		   Otherwise, enable the entry, and set up it's error state based on
		   whether it is empty or not (it should not be). */
		if (nm_streq (tls_remote_mode, TLS_REMOTE_MODE_NONE)) {
			entry_enabled = FALSE;
		} else {
			const char *subject = gtk_editable_get_text (GTK_EDITABLE (entry));

			entry_enabled = TRUE;
			entry_has_error = !subject || !subject[0];
			legacy_tls_remote = nm_streq (tls_remote_mode, TLS_REMOTE_MODE_LEGACY);
		}
	}

	gtk_widget_set_sensitive (entry, entry_enabled);
	if(entry_has_error) {
		widget_set_error (entry);
		gtk_widget_set_sensitive (ok_button, FALSE);
	} else {
		if (legacy_tls_remote) {
			/* selecting tls-remote is not an error, but strongly discouraged. I wish
			 * there would be a warning-class as well. Anyway, mark the widget as
			 * erroneous, although this doesn't make the connection invalid (which
			 * is an ugly inconsistency). */
			widget_set_error (entry);
		} else
			widget_unset_error (entry);
		gtk_widget_set_sensitive (ok_button, TRUE);
	}

}

static void
remote_tls_cert_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_remote_cert_tls = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	use_remote_cert_tls = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_label"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	gtk_widget_set_sensitive (widget, use_remote_cert_tls);
}

#define REMOTE_CERT_COL_NAME 0
#define REMOTE_CERT_COL_VALUE 1

static void
populate_remote_cert_tls_combo (GtkComboBox *box, const char *remote_cert)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Server"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    REMOTE_CERT_COL_NAME, _("Client"),
	                    REMOTE_CERT_COL_VALUE, NM_OPENVPN_REM_CERT_TLS_CLIENT,
	                    -1);

	if (g_strcmp0 (remote_cert, NM_OPENVPN_REM_CERT_TLS_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

#define TLS_AUTH_MODE_NONE     0
#define TLS_AUTH_MODE_AUTH     1
#define TLS_AUTH_MODE_CRYPT    2
#define TLS_AUTH_MODE_CRYPT_V2 3

static void
tls_auth_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gint active;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
	active = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_label"));
	gtk_widget_set_sensitive (widget, active == TLS_AUTH_MODE_AUTH);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
	gtk_widget_set_sensitive (widget, active == TLS_AUTH_MODE_AUTH);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_label"));
	gtk_widget_set_sensitive (widget, active != TLS_AUTH_MODE_NONE);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser_button"));
	gtk_widget_set_sensitive (widget, active != TLS_AUTH_MODE_NONE);
}

static void
ns_cert_type_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_ns_cert_type = FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	use_ns_cert_type = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_label"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	gtk_widget_set_sensitive (widget, use_ns_cert_type);
}

#define NS_CERT_TYPE_COL_NAME 0
#define NS_CERT_TYPE_COL_VALUE 1

static void
populate_ns_cert_type_combo (GtkComboBox *box, const char *type)
{
	GtkListStore *store;
	GtkTreeIter iter;

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_STRING);
	gtk_combo_box_set_model (box, GTK_TREE_MODEL (store));

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Server"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_SERVER,
	                    -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    NS_CERT_TYPE_COL_NAME, _("Client"),
	                    NS_CERT_TYPE_COL_VALUE, NM_OPENVPN_NS_CERT_TYPE_CLIENT,
	                    -1);

	if (g_strcmp0 (type, NM_OPENVPN_NS_CERT_TYPE_CLIENT) == 0)
		gtk_combo_box_set_active (box, 1);
	else
		gtk_combo_box_set_active (box, 0);

	g_object_unref (store);
}

static void
mtu_disc_toggled_cb (GtkWidget *widget, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	gboolean use_mtu_disc;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	use_mtu_disc = gtk_check_button_get_active (GTK_CHECK_BUTTON (widget));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
	gtk_widget_set_sensitive (widget, use_mtu_disc);
}

#define PROXY_TYPE_NONE  0
#define PROXY_TYPE_HTTP  1
#define PROXY_TYPE_SOCKS 2

#define DEVICE_TYPE_IDX_TUN     0
#define DEVICE_TYPE_IDX_TAP     1

#define PING_EXIT    0
#define PING_RESTART 1

static void
proxy_type_changed (GtkComboBox *combo, gpointer user_data)
{
	GtkBuilder *builder = GTK_BUILDER (user_data);
	gboolean sensitive;
	GtkWidget *widget;
	guint32 i = 0;
	int active;
	const char *widgets[] = {
		"proxy_desc_label", "proxy_server_label", "proxy_server_entry",
		"proxy_port_label", "proxy_port_spinbutton", "proxy_retry_checkbutton",
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};
	const char *user_pass_widgets[] = {
		"proxy_username_label", "proxy_password_label", "proxy_username_entry",
		"proxy_password_entry", "show_proxy_password", NULL
	};

	active = gtk_combo_box_get_active (combo);
	sensitive = (active > PROXY_TYPE_NONE);

	while (widgets[i]) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, widgets[i++]));
		gtk_widget_set_sensitive (widget, sensitive);
	}

	/* Additionally user/pass widgets need to be disabled for SOCKS */
	if (active == PROXY_TYPE_SOCKS) {
		i = 0;
		while (user_pass_widgets[i]) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, user_pass_widgets[i++]));
			gtk_widget_set_sensitive (widget, FALSE);
		}
	}

	/* Proxy options require TCP; but don't reset the TCP checkbutton
	 * to false when the user disables HTTP proxy; leave it checked. */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (sensitive == TRUE)
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
	gtk_widget_set_sensitive (widget, !sensitive);
}

static void
show_proxy_password_toggled_cb (GtkCheckButton *button, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *widget;
	gboolean visible;

	visible = gtk_check_button_get_active (GTK_CHECK_BUTTON (button));
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	gtk_entry_set_visibility (GTK_ENTRY (widget), visible);
}

static void
device_name_filter_cb (GtkEntry *entry,
                       const gchar *text,
                       gint length,
                       gint *position,
                       void *user_data)
{
	int i, count = 0;
	gchar *result = g_new (gchar, length + 1);
	GtkEditable *editable = GTK_EDITABLE (entry);

	for (i = 0; i < length; i++) {
		if (text[i] == '/' || g_ascii_isspace (text[i]))
			continue;
		result[count++] = text[i];
	}
	result[count] = 0;

	if (count > 0) {
		g_signal_handlers_block_by_func (G_OBJECT (editable),
		                                 G_CALLBACK (device_name_filter_cb),
		                                 user_data);
		gtk_editable_insert_text (editable, result, count, position);
		g_signal_handlers_unblock_by_func (G_OBJECT (editable),
		                                   G_CALLBACK (device_name_filter_cb),
		                                   user_data);
	}
	g_signal_stop_emission_by_name (G_OBJECT (editable), "insert-text");

	g_free (result);
}

static gboolean
device_name_changed_cb (GtkEntry *entry,
                        gpointer user_data)
{
	GtkEditable *editable = GTK_EDITABLE (entry);
	GtkWidget *ok_button = user_data;
	gboolean entry_sensitive;
	char *entry_text;

	entry_sensitive = gtk_widget_get_sensitive (GTK_WIDGET (entry));
	entry_text = gtk_editable_get_chars (editable, 0, -1);

	/* Change cell's background to red if the value is invalid */
	if (   entry_sensitive
	    && entry_text[0] != '\0'
	    && !_nm_utils_is_valid_iface_name (entry_text)) {
		widget_set_error (GTK_WIDGET (editable));
		gtk_widget_set_sensitive (ok_button, FALSE);
	} else {
		widget_unset_error (GTK_WIDGET (editable));
		gtk_widget_set_sensitive (ok_button, TRUE);
	}

	g_free (entry_text);
	return FALSE;
}

static void
crl_file_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *other, *combo;

	other = GTK_WIDGET (gtk_builder_get_object (builder, "crl_dir_check"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "crl_file_chooser_button"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (check))) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (other), FALSE);
		gtk_widget_set_sensitive (combo, TRUE);
	} else
		gtk_widget_set_sensitive (combo, FALSE);
}

static void
crl_dir_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *other, *combo;

	other = GTK_WIDGET (gtk_builder_get_object (builder, "crl_file_check"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "crl_dir_chooser_button"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (check))) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (other), FALSE);
		gtk_widget_set_sensitive (combo, TRUE);
	} else
		gtk_widget_set_sensitive (combo, FALSE);
}

static void
dev_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *entry, *ok_button;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));

	/* Set values to default ones */
	if (!gtk_check_button_get_active (GTK_CHECK_BUTTON (check))) {
		gtk_editable_set_text (GTK_EDITABLE (entry), "");
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), DEVICE_TYPE_IDX_TUN);
	}

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, entry);
	device_name_changed_cb (GTK_ENTRY (entry), ok_button);
}

static gboolean
_hash_get_boolean (GHashTable *hash,
                   const char *key)
{
	const char *value;

	nm_assert (hash);
	nm_assert (key && key[0]);

	value = g_hash_table_lookup (hash, key);

	return nm_streq0 (value, "yes");
}

static GtkWidget *
_builder_init_toggle_button (GtkBuilder *builder,
                             const char *widget_name,
                             gboolean active_state)
{
	GtkWidget *widget;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
	g_return_val_if_fail (GTK_IS_CHECK_BUTTON (widget), NULL);

	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), active_state);
	return widget;
}

static void
_builder_init_optional_spinbutton (GtkBuilder *builder,
                                   const char *checkbutton_name,
                                   const char *spinbutton_name,
                                   gboolean active_state,
                                   gint64 value)
{
	GtkWidget *widget;
	GtkWidget *spin;

	widget = (GtkWidget *) gtk_builder_get_object (builder, checkbutton_name);
	g_return_if_fail (GTK_IS_CHECK_BUTTON (widget));

	spin = (GtkWidget *) gtk_builder_get_object (builder, spinbutton_name);
	g_return_if_fail (GTK_IS_SPIN_BUTTON (spin));

	g_signal_connect ((GObject *) widget, "toggled", G_CALLBACK (checkbox_toggled_update_widget_cb), spin);

	gtk_spin_button_set_value ((GtkSpinButton *) spin, (double) value);

	gtk_widget_set_sensitive (spin, active_state);
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), active_state);
}

static void
ping_exit_restart_checkbox_toggled_cb (GtkWidget *check, gpointer user_data)
{
	GtkBuilder *builder = (GtkBuilder *) user_data;
	GtkWidget *combo, *spin;

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));

	checkbox_toggled_update_widget_cb (check, combo);
	checkbox_toggled_update_widget_cb (check, spin);
}

#define TA_DIR_COL_NAME 0
#define TA_DIR_COL_NUM 1

static GtkWidget *
advanced_dialog_new (GHashTable *hash, const char *contype)
{
	GtkBuilder *builder;
	GtkWidget *dialog = NULL;
	GtkWidget *widget, *combo, *spin, *entry, *ok_button;
	GtkWidget *chooser;
	GFile *file = NULL;
	GtkLabel *label;
	const char *value, *value2, *value3;
	const char *dev, *dev_type, *tap_dev;
	GtkListStore *store;
	GtkTreeIter iter;
	int vint;
	guint32 active;
	NMSettingSecretFlags pw_flags;
	GError *error = NULL;
	NMOvpnComp comp;
	NMOvpnAllowCompression allow_compression;

	g_return_val_if_fail (hash != NULL, NULL);

	builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (builder, "/org/freedesktop/network-manager-openvpn/nm-openvpn-dialog.ui", &error)) {
		g_error_free (error);
		g_object_unref (G_OBJECT (builder));
		g_return_val_if_reached (NULL);
	}

	dialog = GTK_WIDGET (gtk_builder_get_object (builder, "openvpn-advanced-dialog"));
	if (!dialog) {
		g_object_unref (G_OBJECT (builder));
		g_return_val_if_reached (NULL);
	}
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);

	g_object_set_data_full (G_OBJECT (dialog), "builder",
	                        builder, (GDestroyNotify) g_object_unref);
	g_object_set_data_full (G_OBJECT (dialog), "connection-type", g_strdup (contype), g_free);

	ok_button = GTK_WIDGET (gtk_builder_get_object (builder, "ok_button"));


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_RENEG_SECONDS);
	_builder_init_optional_spinbutton (builder, "reneg_checkbutton", "reneg_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXINT, 0));


	/* Proxy support */
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("Not required"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("HTTP"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("SOCKS"), -1);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_SERVER);
	value2 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_PORT);
	if (   value && *value
	    && value2 && *value2) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);

		vint = _nm_utils_ascii_str_to_int64 (value2, 10, 0, 65535, 0);
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
		gtk_spin_button_set_value (GTK_SPIN_BUTTON (widget), (gdouble) vint);

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_RETRY);
		if (value && !strcmp (value, "yes"))
			gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
		if (value && *value) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD);
		if (value && *value) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
		}

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD_FLAGS);
		G_STATIC_ASSERT_EXPR (((guint) (NMSettingSecretFlags) 0xFFFFu) == 0xFFFFu);
		pw_flags = _nm_utils_ascii_str_to_int64 (value, 10, 0, 0xFFFF, NM_SETTING_SECRET_FLAG_NONE);
	} else
		pw_flags = NM_SETTING_SECRET_FLAG_AGENT_OWNED;

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
	nma_utils_setup_password_storage (widget, pw_flags, NULL, NULL,
	                                  TRUE, FALSE);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PROXY_TYPE);
	active = PROXY_TYPE_NONE;
	if (value) {
		if (!strcmp (value, "http"))
			active = PROXY_TYPE_HTTP;
		else if (!strcmp (value, "socks"))
			active = PROXY_TYPE_SOCKS;
	}

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);
	proxy_type_changed (GTK_COMBO_BOX (combo), builder);
	g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (proxy_type_changed), builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "show_proxy_password"));
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (show_proxy_password_toggled_cb), builder);


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PORT);
	_builder_init_optional_spinbutton (builder, "port_checkbutton", "port_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 1194));


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TUNNEL_MTU);
	_builder_init_optional_spinbutton (builder, "tunmtu_checkbutton", "tunmtu_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 1500));

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CONNECT_TIMEOUT);
	_builder_init_optional_spinbutton (builder, "connect_timeout_checkbutton", "connect_timeout_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, G_MAXINT, 120));

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	_builder_init_optional_spinbutton (builder, "fragment_checkbutton", "fragment_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, 65535, 1300));

	allow_compression = nmovpn_allow_compression_from_options (g_hash_table_lookup (hash, NM_OPENVPN_KEY_ALLOW_COMPRESSION));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "compression-direction-combo"));

	if (allow_compression != NMOVPN_ALLOW_COMPRESSION_NO)
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), allow_compression - 1);

	comp = nmovpn_compression_from_options (g_hash_table_lookup (hash, NM_OPENVPN_KEY_COMP_LZO),
	                                        g_hash_table_lookup (hash, NM_OPENVPN_KEY_COMPRESS));

	combo = GTK_WIDGET (gtk_builder_get_object (builder, "compress_combo"));
	widget = _builder_init_toggle_button (builder, "compress_checkbutton",
	                                      (allow_compression != NMOVPN_ALLOW_COMPRESSION_NO && comp != NMOVPN_COMP_DISABLED));
	g_object_bind_property (widget, "active", combo, "sensitive", G_BINDING_SYNC_CREATE);
	if (comp != NMOVPN_COMP_DISABLED)
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), comp - 1);

	_builder_init_toggle_button (builder, "mssfix_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_MSSFIX));
	_builder_init_toggle_button (builder, "float_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_FLOAT));
	_builder_init_toggle_button (builder, "tcp_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_PROTO_TCP));
	_builder_init_toggle_button (builder, "ncp_disable_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_NCP_DISABLE));

	/* Populate device-related widgets */
	dev =      g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV);
	dev_type = g_hash_table_lookup (hash, NM_OPENVPN_KEY_DEV_TYPE);
	tap_dev =  g_hash_table_lookup (hash, NM_OPENVPN_KEY_TAP_DEV);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), (dev && *dev) || dev_type || tap_dev);
	dev_checkbox_toggled_cb (widget, builder);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (dev_checkbox_toggled_cb), builder);
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
	active = DEVICE_TYPE_IDX_TUN;
	if (   !g_strcmp0 (dev_type, "tap")
	    || (!dev_type && dev && g_str_has_prefix (dev, "tap"))
	    || (!dev_type && !g_strcmp0 (tap_dev, "yes")))
		active = DEVICE_TYPE_IDX_TAP;

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TUN"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("TAP"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
	gtk_entry_set_max_length (GTK_ENTRY (entry), 15);  /* interface name is max 15 chars */
	gtk_entry_set_placeholder_text (GTK_ENTRY (entry), _("(automatic)"));
	g_signal_connect (G_OBJECT (entry), "insert-text", G_CALLBACK (device_name_filter_cb), NULL);
	g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (device_name_changed_cb), ok_button);
	gtk_editable_set_text (GTK_EDITABLE (entry), dev ?: "");


	_builder_init_toggle_button (builder, "remote_random_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_REMOTE_RANDOM));
	_builder_init_toggle_button (builder, "remote_random_hostname_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_REMOTE_RANDOM_HOSTNAME));
	_builder_init_toggle_button (builder, "allow_pull_fqdn_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_ALLOW_PULL_FQDN));
	_builder_init_toggle_button (builder, "tun_ipv6_checkbutton", _hash_get_boolean (hash, NM_OPENVPN_KEY_TUN_IPV6));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CIPHER);
	populate_cipher_combo (GTK_COMBO_BOX (widget), value);


	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_KEYSIZE);
	_builder_init_optional_spinbutton (builder, "keysize_checkbutton", "keysize_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 128));


	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_AUTH);
	populate_hmacauth_combo (GTK_COMBO_BOX (widget), value);

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
	populate_tls_remote_mode_entry_combo (GTK_EDITABLE (entry), GTK_COMBO_BOX (combo),
	                                      g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_REMOTE),
	                                      g_hash_table_lookup (hash, NM_OPENVPN_KEY_VERIFY_X509_NAME));
	g_signal_connect (G_OBJECT (entry), "changed", G_CALLBACK (tls_remote_changed), builder);
	g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (tls_remote_changed), builder);
	tls_remote_changed (entry, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	if (value && *value)
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (remote_tls_cert_toggled_cb), builder);
	remote_tls_cert_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_REMOTE_CERT_TLS);
	populate_remote_cert_tls_combo (GTK_COMBO_BOX (widget), value);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	if (value && *value)
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (ns_cert_type_toggled_cb), builder);
	ns_cert_type_toggled_cb (widget, builder);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_NS_CERT_TYPE);
	populate_ns_cert_type_combo (GTK_COMBO_BOX (widget), value);

	/* TLS auth chooser */
	chooser = GTK_WIDGET(gtk_builder_get_object (builder, "tls_auth_chooser"));
	label = GTK_LABEL (gtk_builder_get_object (builder, "tls_auth_chooser_label"));
	gtk_window_set_hide_on_close (GTK_WINDOW(chooser), TRUE);
	g_signal_connect (G_OBJECT (chooser), "response",
	                  G_CALLBACK (chooser_response), label);
	g_signal_connect_swapped (gtk_builder_get_object (builder, "tls_auth_chooser_button"),
	                          "clicked", G_CALLBACK (gtk_widget_show), chooser);
	if (NM_IN_STRSET (contype,
	                  NM_OPENVPN_CONTYPE_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Initialize direction combo */
		combo = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
		store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, _("None"), TA_DIR_COL_NUM, -1, -1);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "0", TA_DIR_COL_NUM, 0, -1);
		gtk_list_store_append (store, &iter);
		gtk_list_store_set (store, &iter, TA_DIR_COL_NAME, "1", TA_DIR_COL_NUM, 1, -1);
		gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
		g_object_unref (store);
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA);
		value2 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_CRYPT);
		value3 = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_CRYPT_V2);
		if (value3 && value3[0]) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_CRYPT_V2);
			file = g_file_new_for_path (value3);
		} else if (value2 && value2[0]) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_CRYPT);
			file = g_file_new_for_path (value2);
		} else if (value && value[0]) {
			int direction;

			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_AUTH);
			file = g_file_new_for_path (value);
			value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TA_DIR);
			direction = _nm_utils_ascii_str_to_int64 (value, 10, 0, 1, -1);
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
			gtk_combo_box_set_active (GTK_COMBO_BOX (widget), direction + 1);
		} else
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), TLS_AUTH_MODE_NONE);
	}
	if (file)
		gtk_file_chooser_set_file (GTK_FILE_CHOOSER (chooser), file, NULL);
	chooser_button_update_file (label, file);
	g_clear_object (&file);

	/* Extra certs */
	chooser = GTK_WIDGET(gtk_builder_get_object (builder, "extra_certs_chooser"));
	label = GTK_LABEL (gtk_builder_get_object (builder, "extra_certs_chooser_label"));
	gtk_window_set_hide_on_close (GTK_WINDOW(chooser), TRUE);
	g_signal_connect (G_OBJECT (chooser), "response",
	                  G_CALLBACK (chooser_response), label);
	g_signal_connect_swapped (gtk_builder_get_object (builder, "extra_certs_chooser_button"),
	                          "clicked", G_CALLBACK (gtk_widget_show), chooser);
	if (NM_IN_STRSET (contype,
	                  NM_OPENVPN_CONTYPE_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                  NM_OPENVPN_CONTYPE_PASSWORD)) {
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_EXTRA_CERTS);
		if (value && value[0]) {
			file = g_file_new_for_path (value);
			gtk_file_chooser_set_file (GTK_FILE_CHOOSER (chooser), file, NULL);
		}
		g_signal_connect (G_OBJECT (combo), "changed", G_CALLBACK (tls_auth_toggled_cb), builder);
		tls_auth_toggled_cb (combo, builder);
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "options_notebook"));
		gtk_notebook_remove_page (GTK_NOTEBOOK (widget), 2);
	}
	chooser_button_update_file (label, file);
	g_clear_object (&file);

	/* TLS cipher string */
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_CIPHER);
	if (value && *value) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_cipher"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}

	/* ping check */
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING);
	_builder_init_optional_spinbutton (builder, "ping_checkbutton", "ping_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 30));


	/* ping-exit / ping-restart */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	spin = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
	combo = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
	g_signal_connect ((GObject *) widget, "toggled", G_CALLBACK (ping_exit_restart_checkbox_toggled_cb), builder);

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_EXIT);
	active = PING_EXIT;
	if (!value) {
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_PING_RESTART);
		if (value)
			active = PING_RESTART;
	}

	store = gtk_list_store_new (1, G_TYPE_STRING);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-exit"), -1);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter, 0, _("ping-restart"), -1);
	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (store));
	g_object_unref (store);
	gtk_combo_box_set_active ((GtkComboBox *) combo, active);

	gtk_spin_button_set_value ((GtkSpinButton *) spin,
	                           (double) _nm_utils_ascii_str_to_int64 (value, 10, 1, 65535, 30));
	gtk_widget_set_sensitive (combo, !!value);
	gtk_widget_set_sensitive (spin, !!value);
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), !!value);

	/* MTU discovery */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MTU_DISC);
	if (value && value[0]) {
		gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), TRUE);
		combo = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
		if (nm_streq (value, "maybe"))
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 1);
		else if (nm_streq (value, "yes"))
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 2);
		else
			gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	}
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (mtu_disc_toggled_cb), builder);
	mtu_disc_toggled_cb (widget, builder);

	/* CRL file */
	widget = GTK_WIDGET(gtk_builder_get_object (builder, "crl_file_chooser"));
	label = GTK_LABEL (gtk_builder_get_object (builder, "crl_file_chooser_label"));
	gtk_window_set_hide_on_close (GTK_WINDOW(widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "response",
	                  G_CALLBACK (chooser_response), label);
	g_signal_connect_swapped (gtk_builder_get_object (builder, "crl_file_chooser_button"),
	                          "clicked", G_CALLBACK (gtk_widget_show), widget);
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CRL_VERIFY_FILE);
	if (value)
		file = g_file_new_for_path (value);
	chooser_button_update_file (label, file);
	g_clear_object (&file);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_file_check"));
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), !!value);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (crl_file_checkbox_toggled_cb), builder);
	crl_file_checkbox_toggled_cb (widget, builder);

	/* CRL directory */
	widget = GTK_WIDGET(gtk_builder_get_object (builder, "crl_dir_chooser"));
	label = GTK_LABEL (gtk_builder_get_object (builder, "crl_dir_chooser_label"));
	gtk_window_set_hide_on_close (GTK_WINDOW(widget), TRUE);
	g_signal_connect (G_OBJECT (widget), "response",
	                  G_CALLBACK (chooser_response), label);
	g_signal_connect_swapped (gtk_builder_get_object (builder, "crl_dir_chooser_button"),
	                          "clicked", G_CALLBACK (gtk_widget_show), widget);
	if (value) {
		/* If CRL file (see above) has been set,
		 * then we ignore the CRL directory */
		value = NULL;
	} else {
		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_CRL_VERIFY_DIR);
	}
	if (value) {
		file = g_file_new_for_path (value);
		gtk_file_chooser_set_file (GTK_FILE_CHOOSER (widget), file, NULL);
	}
	chooser_button_update_file (label, file);
	g_clear_object (&file);
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_dir_check"));
	gtk_check_button_set_active (GTK_CHECK_BUTTON (widget), !!value);
	g_signal_connect (G_OBJECT (widget), "toggled", G_CALLBACK (crl_dir_checkbox_toggled_cb), builder);
	crl_dir_checkbox_toggled_cb (widget, builder);

	/* Max routes */
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_MAX_ROUTES);
	_builder_init_optional_spinbutton (builder, "max_routes_checkbutton", "max_routes_spinbutton", !!value,
	                                   _nm_utils_ascii_str_to_int64 (value, 10, 0, 100000000, 100));

	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_VERSION_MIN);
	if (value && *value) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_min"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);

		value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_VERSION_MIN_OR_HIGHEST);
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_min_or_highest"));
		gtk_check_button_set_active(GTK_CHECK_BUTTON (widget), nm_streq0 (value, "yes"));
	}
	value = g_hash_table_lookup (hash, NM_OPENVPN_KEY_TLS_VERSION_MAX);
	if (value && *value) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_max"));
		gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}

	_builder_init_toggle_button (builder, "push_peer_info_checkbutton",
	                             _hash_get_boolean (hash, NM_OPENVPN_KEY_PUSH_PEER_INFO));

	g_signal_connect_swapped (G_OBJECT (gtk_builder_get_object (builder, "sk_key_chooser_button")),
	                  "clicked", G_CALLBACK (gtk_widget_show),
	                  gtk_builder_get_object (builder, "sk_key_chooser"));

	return dialog;
}

static GHashTable *
advanced_dialog_new_hash_from_dialog (GtkWidget *dialog)
{
	GHashTable *hash;
	GtkWidget *widget, *entry, *combo;
	GtkBuilder *builder;
	const char *contype = NULL;
	const char *value;
	int proxy_type = PROXY_TYPE_NONE;
	GtkTreeModel *model;
	GtkTreeIter iter;

	g_return_val_if_fail (dialog, NULL);

	builder = g_object_get_data (G_OBJECT (dialog), "builder");
	g_return_val_if_fail (builder, NULL);

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int reneg_seconds;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "reneg_spinbutton"));
		reneg_seconds = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_RENEG_SECONDS, g_strdup_printf ("%d", reneg_seconds));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int tunmtu_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "tunmtu_spinbutton"));
		tunmtu_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TUNNEL_MTU, g_strdup_printf ("%d", tunmtu_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "connect_timeout_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int timeout;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "connect_timeout_spinbutton"));
		timeout = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_CONNECT_TIMEOUT, g_strdup_printf ("%d", timeout));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int fragment_size;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "fragment_spinbutton"));
		fragment_size = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_FRAGMENT_SIZE, g_strdup_printf ("%d", fragment_size));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int port;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "port_spinbutton"));
		port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_PORT, g_strdup_printf ("%d", port));
	}

	/* Proxy support */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_type_combo"));
	proxy_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	if (proxy_type != PROXY_TYPE_NONE) {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_server_entry"));
		value = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (value && *value) {
			int proxy_port;

			if (proxy_type == PROXY_TYPE_HTTP)
				g_hash_table_insert (hash, NM_OPENVPN_KEY_PROXY_TYPE, g_strdup ("http"));
			else if (proxy_type == PROXY_TYPE_SOCKS)
				g_hash_table_insert (hash, NM_OPENVPN_KEY_PROXY_TYPE, g_strdup ("socks"));

			g_hash_table_insert (hash, NM_OPENVPN_KEY_PROXY_SERVER, g_strdup (value));

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_port_spinbutton"));
			proxy_port = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
			if (proxy_port > 0) {
				g_hash_table_insert (hash, NM_OPENVPN_KEY_PROXY_PORT,
				                     g_strdup_printf ("%d", proxy_port));
			}

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_retry_checkbutton"));
			if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
				g_hash_table_insert (hash, NM_OPENVPN_KEY_PROXY_RETRY, g_strdup ("yes"));

			if (proxy_type == PROXY_TYPE_HTTP) {
				guint32 pw_flags;

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_username_entry"));
				value = gtk_editable_get_text (GTK_EDITABLE (widget));
				if (value && *value)
					g_hash_table_insert (hash, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME, g_strdup (value));

				widget = GTK_WIDGET (gtk_builder_get_object (builder, "proxy_password_entry"));
				value = gtk_editable_get_text (GTK_EDITABLE (widget));
				if (value && *value)
					g_hash_table_insert (hash, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD, g_strdup (value));

				pw_flags = nma_utils_menu_to_secret_flags (widget);
				if (pw_flags != NM_SETTING_SECRET_FLAG_NONE) {
					g_hash_table_insert (hash,
					                     NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD_FLAGS,
					                     g_strdup_printf ("%d", pw_flags));
				}
			}
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "compress_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		const char *opt_allow_compression;
		const char *opt_compress;
		const char *opt_comp_lzo;
		NMOvpnComp comp;
		NMOvpnAllowCompression allow_compression;

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "compression-direction-combo"));
		allow_compression = gtk_combo_box_get_active (GTK_COMBO_BOX (combo)) + 1;
		nmovpn_allow_compression_to_options (allow_compression, &opt_allow_compression);
		if (opt_allow_compression)
			g_hash_table_insert (hash, NM_OPENVPN_KEY_ALLOW_COMPRESSION, g_strdup (opt_allow_compression));

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "compress_combo"));
		comp = gtk_combo_box_get_active (GTK_COMBO_BOX (combo)) + 1;
		nmovpn_compression_to_options (comp, &opt_comp_lzo, &opt_compress);
		if (opt_compress)
			g_hash_table_insert (hash, NM_OPENVPN_KEY_COMPRESS, g_strdup (opt_compress));
		if (opt_comp_lzo)
			g_hash_table_insert (hash, NM_OPENVPN_KEY_COMP_LZO, g_strdup (opt_comp_lzo));
	} else {
		g_hash_table_insert (hash, NM_OPENVPN_KEY_ALLOW_COMPRESSION, g_strdup ("no"));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mssfix_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_MSSFIX, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "float_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_FLOAT, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tcp_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_PROTO_TCP, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ncp_disable_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_NCP_DISABLE, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int device_type;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_type_combo"));
		device_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
		g_hash_table_insert (hash,
		                     NM_OPENVPN_KEY_DEV_TYPE,
		                     g_strdup (device_type == DEVICE_TYPE_IDX_TUN ? "tun" : "tap"));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "dev_entry"));
		value = gtk_editable_get_text (GTK_EDITABLE (widget));
		if (value && value[0] != '\0')
			g_hash_table_insert (hash, NM_OPENVPN_KEY_DEV, g_strdup (value));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_random_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_REMOTE_RANDOM, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_random_hostname_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_REMOTE_RANDOM_HOSTNAME, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "allow_pull_fqdn_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_ALLOW_PULL_FQDN, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tun_ipv6_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TUN_IPV6, g_strdup ("yes"));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "cipher_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		gs_free char *cipher = NULL;
		gboolean is_default;

		gtk_tree_model_get (model, &iter,
		                    TLS_CIPHER_COL_NAME, &cipher,
		                    TLS_CIPHER_COL_DEFAULT, &is_default, -1);
		if (!is_default && cipher) {
			g_hash_table_insert (hash, NM_OPENVPN_KEY_CIPHER,
			                     g_steal_pointer (&cipher));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int keysize_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "keysize_spinbutton"));
		keysize_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_KEYSIZE, g_strdup_printf ("%d", keysize_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "hmacauth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
		char *hmacauth;

		gtk_tree_model_get (model, &iter,
		                    HMACAUTH_COL_VALUE, &hmacauth,
		                    -1);
		if (hmacauth)
			g_hash_table_insert (hash, NM_OPENVPN_KEY_AUTH, hmacauth);
	}
	entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_min"));
	value = gtk_editable_get_text (GTK_EDITABLE (entry));
	if (value && *value)
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_VERSION_MIN, g_strdup (value));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_min_or_highest"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON(widget))) {
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_VERSION_MIN_OR_HIGHEST, g_strdup ("yes"));
	} else {
		g_hash_table_remove (hash, NM_OPENVPN_KEY_TLS_VERSION_MIN_OR_HIGHEST);
	}

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_version_max"));
	value = gtk_editable_get_text (GTK_EDITABLE (entry));
	if (value && *value)
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_VERSION_MAX, g_strdup (value));

	contype = g_object_get_data (G_OBJECT (dialog), "connection-type");
	if (   !strcmp (contype, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || !strcmp (contype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		char *filename;
		GFile *file;

		entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_entry"));
		value = gtk_editable_get_text (GTK_EDITABLE (entry));

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_remote_mode_combo"));
		model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));

		if (   value && *value
		    && gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter)) {
			gs_free char *tls_remote_mode = NULL;

			gtk_tree_model_get (model, &iter, TLS_REMOTE_MODE_COL_VALUE, &tls_remote_mode, -1);
			if (nm_streq (tls_remote_mode, TLS_REMOTE_MODE_NONE)) {
				// pass
			} else if (nm_streq (tls_remote_mode, TLS_REMOTE_MODE_LEGACY)) {
				g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_REMOTE, g_strdup (value));
			} else {
				g_hash_table_insert (hash,
				                     NM_OPENVPN_KEY_VERIFY_X509_NAME,
				                     g_strdup_printf ("%s:%s", tls_remote_mode, value));
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_checkbutton"));
		if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "remote_cert_tls_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *remote_cert;

				gtk_tree_model_get (model, &iter, REMOTE_CERT_COL_VALUE, &remote_cert, -1);
				if (remote_cert) {
					g_hash_table_insert (hash,
					                     NM_OPENVPN_KEY_REMOTE_CERT_TLS,
					                     remote_cert);
				}
			}
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_checkbutton"));
		if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "ns_cert_type_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				char *type;

				gtk_tree_model_get (model, &iter, NS_CERT_TYPE_COL_VALUE, &type, -1);
				if (type) {
					g_hash_table_insert (hash,
					                     NM_OPENVPN_KEY_NS_CERT_TYPE,
					                     type);
				}
			}
		}

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_mode"));
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
		case TLS_AUTH_MODE_AUTH:
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));

			file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
			if (file)
				filename = g_file_get_path (file);
			else
				filename = NULL;
			if (filename && filename[0])
				g_hash_table_insert (hash, NM_OPENVPN_KEY_TA, g_strdup (filename));
			g_free (filename);
			g_clear_object (&file);

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "direction_combo"));
			model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
			if (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter)) {
				int direction;

				gtk_tree_model_get (model, &iter, TA_DIR_COL_NUM, &direction, -1);
				if (direction >= 0) {
					g_hash_table_insert (hash, NM_OPENVPN_KEY_TA_DIR,
					                     g_strdup_printf ("%d", direction));
				}
			}
			break;
		case TLS_AUTH_MODE_CRYPT:
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
			if (file)
				filename = g_file_get_path (file);
			else
				filename = NULL;
			if (filename && filename[0])
				g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_CRYPT, g_strdup (filename));
			g_free (filename);
			g_clear_object (&file);
			break;
		case TLS_AUTH_MODE_CRYPT_V2:
			widget = GTK_WIDGET (gtk_builder_get_object (builder, "tls_auth_chooser"));
			file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
			if (file)
				filename = g_file_get_path (file);
			else
				filename = NULL;
			if (filename && filename[0])
				g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_CRYPT_V2, g_strdup (filename));
			g_free (filename);
			g_clear_object (&file);
			break;
		case TLS_AUTH_MODE_NONE:
			break;
		}

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "extra_certs_chooser"));
		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
		if (file)
			filename = g_file_get_path (file);
		else
			filename = NULL;
		if (filename && filename[0])
			g_hash_table_insert (hash, NM_OPENVPN_KEY_EXTRA_CERTS, g_strdup (filename));
		g_free (filename);
		g_clear_object (&file);
	}

	entry = GTK_WIDGET (gtk_builder_get_object (builder, "tls_cipher"));
	value = gtk_editable_get_text (GTK_EDITABLE (entry));
	if (value && *value)
		g_hash_table_insert (hash, NM_OPENVPN_KEY_TLS_CIPHER, g_strdup (value));

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     NM_OPENVPN_KEY_PING,
		                     g_strdup_printf ("%d", ping_val));
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int ping_exit_type, ping_val;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_combo"));
		ping_exit_type = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "ping_exit_restart_spinbutton"));
		ping_val = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));

		g_hash_table_insert (hash,
		                     ping_exit_type == PING_EXIT
		                       ? NM_OPENVPN_KEY_PING_EXIT
		                       : NM_OPENVPN_KEY_PING_RESTART,
		                     g_strdup_printf ("%d", ping_val));
	}

	/* max routes */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		int max_routes;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "max_routes_spinbutton"));
		max_routes = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON (widget));
		g_hash_table_insert (hash, NM_OPENVPN_KEY_MAX_ROUTES, g_strdup_printf ("%d", max_routes));
	}

	/* MTU discovery */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		char *val = NULL;

		combo = GTK_WIDGET (gtk_builder_get_object (builder, "mtu_disc_combo"));
		switch (gtk_combo_box_get_active (GTK_COMBO_BOX (combo))) {
		case 0:
			val = "no";
			break;
		case 1:
			val = "maybe";
			break;
		case 2:
			val = "yes";
			break;
		}
		if (val) {
			g_hash_table_insert (hash,
			                     NM_OPENVPN_KEY_MTU_DISC,
			                     g_strdup (val));
		}
	}

	/* CRL */
	widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_file_check"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
		gs_unref_object GFile *file = NULL;
		gs_free char *filename = NULL;

		widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_file_chooser"));
		file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
		if (file)
			filename = g_file_get_path (file);
		if (filename && filename[0])
			g_hash_table_insert (hash, NM_OPENVPN_KEY_CRL_VERIFY_FILE, g_steal_pointer (&filename));
	} else {
		widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_dir_check"));
		if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget))) {
			gs_unref_object GFile *file = NULL;
			gs_free char *filename = NULL;

			widget = GTK_WIDGET (gtk_builder_get_object (builder, "crl_dir_chooser"));
			file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (widget));
			if (file)
				filename = g_file_get_path (file);
			if (filename && filename[0])
				g_hash_table_insert (hash, NM_OPENVPN_KEY_CRL_VERIFY_DIR, g_steal_pointer (&filename));
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (builder, "push_peer_info_checkbutton"));
	if (gtk_check_button_get_active (GTK_CHECK_BUTTON (widget)))
		g_hash_table_insert (hash, NM_OPENVPN_KEY_PUSH_PEER_INFO, g_strdup ("yes"));

	return hash;
}

/*****************************************************************************/

static void openvpn_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpenvpnEditor, openvpn_editor_plugin_widget, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               openvpn_editor_plugin_widget_interface_init))

#define OPENVPN_EDITOR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENVPN_TYPE_EDITOR, OpenvpnEditorPrivate))

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkWindowGroup *window_group;
	gboolean window_added;
	GHashTable *advanced;
	GtkWidget *tls_user_cert_chooser;
	GFile *sk_key_file;
} OpenvpnEditorPrivate;

/*****************************************************************************/

#define COL_AUTH_NAME 0
#define COL_AUTH_PAGE 1
#define COL_AUTH_TYPE 2

static gboolean
check_gateway_entry (const char *str)
{
	gs_free char *str_clone = NULL;
	char *str_iter;
	const char *tok;
	gboolean success = FALSE;

	if (!str || !str[0])
		return FALSE;

	str_clone = g_strdup (str);
	str_iter = str_clone;
	while ((tok = strsep (&str_iter, " \t,"))) {
		if (!tok[0])
			continue;
		if (nmovpn_remote_parse (tok,
		                         NULL,
		                         NULL,
		                         NULL,
		                         NULL,
		                         NULL) != -1)
		   return FALSE;
		success = TRUE;
	}
	return success;
}

static gboolean
check_validity (OpenvpnEditor *self, GError **error)
{
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gs_free char *contype = NULL;
	gboolean success;

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && check_gateway_entry (str))
		gtk_style_context_remove_class (gtk_widget_get_style_context (widget), "error");
	else {
		gtk_style_context_add_class (gtk_widget_get_style_context (widget), "error");
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY,
		             NM_OPENVPN_KEY_REMOTE);
		return FALSE;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_return_val_if_fail (model, FALSE);
	success = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	g_return_val_if_fail (success == TRUE, FALSE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);
	if (!auth_widget_check_validity (priv->builder, contype, error))
		return FALSE;

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENVPN_EDITOR (user_data), "changed");
}

static void
auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *auth_notebook;
	GtkTreeModel *model;
	GtkTreeIter iter;
	int new_page;

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter));
	gtk_tree_model_get (model, &iter, COL_AUTH_PAGE, &new_page, -1);

	auth_notebook = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_notebook"));
	gtk_notebook_set_current_page (GTK_NOTEBOOK (auth_notebook), new_page);

	stuff_changed_cb (combo, self);
}

static void
advanced_dialog_close_cb (GtkWidget *dialog, gpointer user_data)
{
	gtk_widget_hide (dialog);
	/* gtk_window_destroy() will remove the window from the window group */
	gtk_window_destroy (GTK_WINDOW (dialog));
}

static void
advanced_dialog_response_cb (GtkWidget *dialog, gint response, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);

	if (response != GTK_RESPONSE_OK) {
		advanced_dialog_close_cb (dialog, self);
		return;
	}

	nm_clear_pointer (&priv->advanced, g_hash_table_destroy);
	priv->advanced = advanced_dialog_new_hash_from_dialog (dialog);
	advanced_dialog_close_cb (dialog, self);

	stuff_changed_cb (NULL, self);
}

static void
advanced_button_clicked_cb (GtkWidget *button, gpointer user_data)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (user_data);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	GtkWidget *dialog, *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	gs_free char *contype = NULL;
	gboolean success;
	GtkRoot *root;

	root = gtk_widget_get_root (priv->widget);
	g_return_if_fail (GTK_IS_WINDOW(root));

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	success = gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	g_return_if_fail (success == TRUE);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &contype, -1);

	dialog = advanced_dialog_new (priv->advanced, contype);
	if (!dialog) {
		g_warning ("%s: failed to create the Advanced dialog!", __func__);
		return;
	}

	gtk_window_group_add_window (priv->window_group, GTK_WINDOW (dialog));
	if (!priv->window_added) {
		gtk_window_group_add_window (priv->window_group, GTK_WINDOW (root));
		priv->window_added = TRUE;
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (root));
	g_signal_connect (G_OBJECT (dialog), "response", G_CALLBACK (advanced_dialog_response_cb), self);
	g_signal_connect (G_OBJECT (dialog), "close", G_CALLBACK (advanced_dialog_close_cb), self);

	gtk_widget_show (dialog);
}

static void
sk_key_chooser_response (GtkDialog *chooser, gint response_id, gpointer user_data)
{
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (user_data);

	if (response_id == GTK_RESPONSE_ACCEPT) {
		g_clear_object (&priv->sk_key_file);
		priv->sk_key_file = gtk_file_chooser_get_file (GTK_FILE_CHOOSER (chooser));
		stuff_changed_cb (GTK_WIDGET (chooser), user_data);
	} else {
		gtk_file_chooser_set_file (GTK_FILE_CHOOSER (chooser), priv->sk_key_file, NULL);
	}
}

static gboolean
init_editor_plugin (OpenvpnEditor *self, NMConnection *connection)
{
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	const char *value;
	const char *contype = NM_OPENVPN_CONTYPE_TLS;

	s_vpn = nm_connection_get_setting_vpn (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	g_return_val_if_fail (widget != NULL, FALSE);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
		if (value)
			gtk_editable_set_text (GTK_EDITABLE (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "auth_combo"));
	g_return_val_if_fail (widget != NULL, FALSE);

	store = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

	if (s_vpn) {
		contype = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
		if (!NM_IN_STRSET (contype, NM_OPENVPN_CONTYPE_TLS,
		                            NM_OPENVPN_CONTYPE_STATIC_KEY,
		                            NM_OPENVPN_CONTYPE_PASSWORD,
		                            NM_OPENVPN_CONTYPE_PASSWORD_TLS))
			contype = NM_OPENVPN_CONTYPE_TLS;
	}

	/* TLS auth widget */
	tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_TLS, "tls",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Certificates (TLS)"),
	                    COL_AUTH_PAGE, 0,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_TLS,
	                    -1);

	/* Password auth widget */
	tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD, "pw",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password"),
	                    COL_AUTH_PAGE, 1,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD,
	                    -1);
	if (   active < 0
	    && nm_streq (contype, NM_OPENVPN_CONTYPE_PASSWORD))
		active = 1;

	/* Password+TLS auth widget */
	tls_pw_init_auth_widget (priv->builder, s_vpn,
	                         NM_OPENVPN_CONTYPE_PASSWORD_TLS, "pw_tls",
	                         stuff_changed_cb, self);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Password with Certificates (TLS)"),
	                    COL_AUTH_PAGE, 2,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_PASSWORD_TLS,
	                    -1);
	if (   active < 0
	    && nm_streq (contype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
		active = 2;

	/* Static key auth widget */
	sk_init_auth_widget (priv->builder, s_vpn, stuff_changed_cb, self);

	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_AUTH_NAME, _("Static Key"),
	                    COL_AUTH_PAGE, 3,
	                    COL_AUTH_TYPE, NM_OPENVPN_CONTYPE_STATIC_KEY,
	                    -1);
	if (   active < 0
	    && nm_streq (contype, NM_OPENVPN_CONTYPE_STATIC_KEY))
		active = 3;

	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (auth_combo_changed_cb), self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "sk_key_chooser"));
	g_signal_connect (G_OBJECT (widget), "response", G_CALLBACK (sk_key_chooser_response), self);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "advanced_button"));
	g_signal_connect (G_OBJECT (widget), "clicked", G_CALLBACK (advanced_button_clicked_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnEditor *iface)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (iface);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static void
hash_copy_advanced (gpointer key, gpointer data, gpointer user_data)
{
	NMSettingVpn *s_vpn = NM_SETTING_VPN (user_data);
	const char *value = data;

	g_return_if_fail (value && *value);

	/* HTTP Proxy password is a secret, not a data item */
	if (nm_streq0 (key, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD))
		nm_setting_vpn_add_secret (s_vpn, (const char *) key, value);
	else
		nm_setting_vpn_add_data_item (s_vpn, (const char *) key, value);
}

static char *
get_auth_type (GtkBuilder *builder)
{
	GtkComboBox *combo;
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *auth_type;
	gboolean success;

	combo = GTK_COMBO_BOX (GTK_WIDGET (gtk_builder_get_object (builder, "auth_combo")));
	model = gtk_combo_box_get_model (combo);

	success = gtk_combo_box_get_active_iter (combo, &iter);
	g_return_val_if_fail (success == TRUE, NULL);
	gtk_tree_model_get (model, &iter, COL_AUTH_TYPE, &auth_type, -1);
	return auth_type;
}

static gboolean
update_connection (NMVpnEditor *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpenvpnEditor *self = OPENVPN_EDITOR (iface);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	GtkWidget *widget;
	gs_free char *auth_type = NULL;
	const char *str;
	gboolean valid = FALSE;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_VPN_SERVICE_TYPE_OPENVPN, NULL);

	widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "gateway_entry"));
	str = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (str && str[0])
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE, str);

	auth_type = get_auth_type (priv->builder);
	if (auth_type) {
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE, auth_type);
		auth_widget_update_connection (priv->builder, auth_type, s_vpn);
	}

	if (priv->advanced)
		g_hash_table_foreach (priv->advanced, hash_copy_advanced, s_vpn);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static void
is_new_func (const char *key, const char *value, gpointer user_data)
{
	gboolean *is_new = user_data;

	/* If there are any VPN data items the connection isn't new */
	*is_new = FALSE;
}

/*****************************************************************************/

static void
openvpn_editor_plugin_widget_init (OpenvpnEditor *plugin)
{
}

NMVpnEditor *
openvpn_editor_new (NMConnection *connection, GError **error)
{
	gs_unref_object NMVpnEditor *object = NULL;
	OpenvpnEditorPrivate *priv;
	gboolean new = TRUE;
	NMSettingVpn *s_vpn;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	object = g_object_new (OPENVPN_TYPE_EDITOR, NULL);

	priv = OPENVPN_EDITOR_GET_PRIVATE (object);

	priv->builder = gtk_builder_new ();

	gtk_builder_set_translation_domain (priv->builder, GETTEXT_PACKAGE);

	if (!gtk_builder_add_from_resource (priv->builder, "/org/freedesktop/network-manager-openvpn/nm-openvpn-dialog.ui", error))
		g_return_val_if_reached (NULL);

	priv->widget = GTK_WIDGET (gtk_builder_get_object (priv->builder, "openvpn-vbox"));
	if (!priv->widget) {
		g_set_error_literal (error, NMV_EDITOR_PLUGIN_ERROR, 0, _("could not load UI widget"));
		g_return_val_if_reached (NULL);
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (s_vpn)
		nm_setting_vpn_foreach_data_item (s_vpn, is_new_func, &new);

	if (new && s_vpn) {
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_OPENVPN_KEY_PASSWORD,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
		nm_setting_set_secret_flags (NM_SETTING (s_vpn),
		                             NM_OPENVPN_KEY_CERTPASS,
		                             NM_SETTING_SECRET_FLAG_AGENT_OWNED,
		                             NULL);
	}

	if (!init_editor_plugin (OPENVPN_EDITOR (object), connection))
		g_return_val_if_reached (NULL);

	priv->advanced = advanced_dialog_new_hash_from_connection (connection);

	/*
	 * There's no way in Gtk file chooser to unselect a file.
	 * Sigh. Use a lame duck one instead.
	 */
	priv->sk_key_file = g_file_new_for_path ("");

	return g_steal_pointer (&object);
}

static void
dispose (GObject *object)
{
	OpenvpnEditor *plugin = OPENVPN_EDITOR (object);
	OpenvpnEditorPrivate *priv = OPENVPN_EDITOR_GET_PRIVATE (plugin);

	g_clear_object (&priv->window_group);

	g_clear_object (&priv->widget);

	g_clear_object (&priv->builder);

	g_clear_pointer (&priv->advanced, g_hash_table_destroy);

	g_clear_object (&priv->sk_key_file);

	G_OBJECT_CLASS (openvpn_editor_plugin_widget_parent_class)->dispose (object);
}

static void
openvpn_editor_plugin_widget_interface_init (NMVpnEditorInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

static void
openvpn_editor_plugin_widget_class_init (OpenvpnEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpenvpnEditorPrivate));

	object_class->dispose = dispose;
}

/*****************************************************************************/

#include "nm-openvpn-editor-plugin.h"

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_openvpn (NMVpnEditorPlugin *editor_plugin,
                               NMConnection *connection,
                               GError **error)
{
	g_type_ensure (NMA_TYPE_CERT_CHOOSER);
	return openvpn_editor_new (connection, error);
}
