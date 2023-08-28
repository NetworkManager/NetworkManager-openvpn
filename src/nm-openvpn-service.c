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
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2010 Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2008 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>
#include <glib-unix.h>

#include "utils.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

#define RUNDIR  LOCALSTATEDIR"/run/NetworkManager"

static struct {
	gboolean debug;
	int log_level;
	int log_level_ovpn;
	bool log_syslog;
	GSList *pids_pending_list;
} gl/*obal*/;

#define NM_OPENVPN_HELPER_PATH LIBEXECDIR"/nm-openvpn-service-openvpn-helper"

/*****************************************************************************/

#define NM_TYPE_OPENVPN_PLUGIN            (nm_openvpn_plugin_get_type ())
#define NM_OPENVPN_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPlugin))
#define NM_OPENVPN_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))
#define NM_IS_OPENVPN_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENVPN_PLUGIN))
#define NM_IS_OPENVPN_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OPENVPN_PLUGIN))
#define NM_OPENVPN_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMOpenvpnPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMOpenvpnPluginClass;

GType nm_openvpn_plugin_get_type (void);

NMOpenvpnPlugin *nm_openvpn_plugin_new (const char *bus_name);

/*****************************************************************************/

typedef enum {
	OPENVPN_BINARY_VERSION_INVALID,
	OPENVPN_BINARY_VERSION_UNKNOWN,
	OPENVPN_BINARY_VERSION_2_3_OR_OLDER,
	OPENVPN_BINARY_VERSION_2_4_OR_NEWER,
} OpenvpnBinaryVersion;

typedef struct {
	GPid pid;
	guint watch_id;
	guint kill_id;
	NMOpenvpnPlugin *plugin;
	bool is_terminating:1;
} PidsPendingData;

typedef struct {
	char *default_username;
	char *username;
	char *password;
	char *priv_key_pass;
	char *proxy_username;
	char *proxy_password;
	char *pending_auth;
	char *challenge_state_id;
	char *challenge_text;
	GIOChannel *socket_channel;
	guint socket_channel_eventid;
} NMOpenvpnPluginIOData;

typedef struct {
	GPid pid;
	guint connect_timer;
	guint connect_count;
	NMOpenvpnPluginIOData *io_data;
	gboolean interactive;
	char *mgt_path;
} NMOpenvpnPluginPrivate;

G_DEFINE_TYPE (NMOpenvpnPlugin, nm_openvpn_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_OPENVPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginPrivate))

/*****************************************************************************/

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
	gboolean address;
} ValidProperty;

static const ValidProperty valid_properties[] = {
	{ NM_OPENVPN_KEY_ALLOW_PULL_FQDN,           G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_AUTH,                      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CA,                        G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERT,                      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CIPHER,                    G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_KEYSIZE,                   G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_COMPRESS,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_COMP_LZO,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CONNECT_TIMEOUT,           G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_CONNECTION_TYPE,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CRL_VERIFY_FILE,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CRL_VERIFY_DIR,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_EXTRA_CERTS,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_FLOAT,                     G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NCP_DISABLE,               G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_FRAGMENT_SIZE,             G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_KEY,                       G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_LOCAL_IP,                  G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_MSSFIX,                    G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_MTU_DISC,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PING,                      G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_PING_EXIT,                 G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_PING_RESTART,              G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_MAX_ROUTES,                G_TYPE_INT, 0, 100000000, FALSE },
	{ NM_OPENVPN_KEY_PROTO_TCP,                 G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PORT,                      G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_PROXY_TYPE,                G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PROXY_SERVER,              G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PROXY_PORT,                G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_PROXY_RETRY,               G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PUSH_PEER_INFO,            G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_USERNAME,       G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE,                    G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_RANDOM,             G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_RANDOM_HOSTNAME,    G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_IP,                 G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_RENEG_SECONDS,             G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_STATIC_KEY,                G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_STATIC_KEY_DIRECTION,      G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_TA,                        G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TA_DIR,                    G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_TAP_DEV,                   G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_DEV,                       G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_DEV_TYPE,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TUN_IPV6,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_CIPHER,                G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_CRYPT,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_CRYPT_V2,              G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_REMOTE,                G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_VERIFY_X509_NAME,          G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_CERT_TLS,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NS_CERT_TYPE,              G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TUNNEL_MTU,                G_TYPE_INT, 0, G_MAXINT, FALSE },
	{ NM_OPENVPN_KEY_USERNAME,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PASSWORD_FLAGS,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERTPASS_FLAGS,            G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NOSECRET,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD_FLAGS, G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_VERSION_MIN,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TLS_VERSION_MAX,           G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                     G_TYPE_NONE, FALSE }
};

static const ValidProperty valid_secrets[] = {
	{ NM_OPENVPN_KEY_PASSWORD,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERTPASS,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD,  G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

/*****************************************************************************/

#define _NMLOG(level, ...) \
	G_STMT_START { \
		if (gl.log_level >= (level)) { \
			g_print ("nm-openvpn[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         (long) getpid (), \
			         nm_utils_syslog_to_str (level) \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

static gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static gboolean
validate_connection_type (const char *ctype)
{
	return NM_IN_STRSET (ctype, NM_OPENVPN_CONTYPE_TLS,
	                            NM_OPENVPN_CONTYPE_STATIC_KEY,
	                            NM_OPENVPN_CONTYPE_PASSWORD,
	                            NM_OPENVPN_CONTYPE_PASSWORD_TLS);
}

static gboolean
connection_type_is_tls_mode (const char *connection_type)
{
	return NM_IN_STRSET (connection_type, NM_OPENVPN_CONTYPE_TLS,
	                                      NM_OPENVPN_CONTYPE_PASSWORD,
	                                      NM_OPENVPN_CONTYPE_PASSWORD_TLS);
}

/*****************************************************************************/

static void
args_add_str_take (GPtrArray *args, char *arg)
{
	nm_assert (args);
	nm_assert (arg);

	g_ptr_array_add (args, arg);
}

static void
_args_add_strv (GPtrArray *args, gboolean accept_optional, guint argn, ...)
{
	va_list ap;
	guint i;
	const char *arg;

	nm_assert (args);
	nm_assert (argn > 0);

	va_start (ap, argn);
	for (i = 0; i < argn; i++) {
		arg = va_arg (ap, const char *);
		if (!arg) {
			/* for convenience for the caller, we allow to pass %NULL with the
			 * meaning to skip the argument. */
			nm_assert (accept_optional);
			continue;
		}
		args_add_str_take (args, g_strdup (arg));
	}
	va_end (ap);
}
#define args_add_strv(args, ...)  _args_add_strv (args, FALSE, NM_NARG (__VA_ARGS__), __VA_ARGS__)
#define args_add_strv0(args, ...) _args_add_strv (args, TRUE,  NM_NARG (__VA_ARGS__), __VA_ARGS__)

static const char *
args_add_utf8safe_str (GPtrArray *args, const char *arg)
{
	char *arg_unescaped;

	nm_assert (args);
	nm_assert (arg);

	arg_unescaped = nm_utils_str_utf8safe_unescape_cp (arg);
	args_add_str_take (args, arg_unescaped);
	return arg_unescaped;
}

static void
args_add_int64 (GPtrArray *args, gint64 v)
{
	nm_assert (args);

	args_add_str_take (args, g_strdup_printf ("%"G_GINT64_FORMAT, v));
}

static gboolean
args_add_numstr (GPtrArray *args, const char *arg)
{
	gint64 v;

	nm_assert (args);
	nm_assert (arg);

	/* Convert to int and for security's sake and to normalize the value
	 * and also to gracefully handle leading and trailing whitespace. */
	v = _nm_utils_ascii_str_to_int64 (arg, 10, G_MININT64, G_MAXINT64, 0);
	if (!v && errno)
		return FALSE;
	args_add_int64 (args, v);
	return TRUE;
}

static void
args_add_vpn_data (GPtrArray *args, NMSettingVpn *s_vpn, const char *s_key, const char *a_key)
{
	const char *arg;

	nm_assert (args);
	nm_assert (NM_IS_SETTING_VPN (s_vpn));
	nm_assert (s_key && s_key[0]);
	nm_assert (a_key && a_key[0]);

	arg = nm_setting_vpn_get_data_item (s_vpn, s_key);
	if (nmovpn_arg_is_set (arg))
		args_add_strv (args, a_key, arg);
}

static void
args_add_vpn_certs (GPtrArray *args, NMSettingVpn *s_vpn)
{
	const char *ca, *cert, *key;
	gs_free char *ca_free = NULL, *cert_free = NULL, *key_free = NULL;

	nm_assert (args);
	nm_assert (NM_IS_SETTING_VPN (s_vpn));

	ca   = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
	cert = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CERT);
	key  = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);

	ca   = nm_utils_str_utf8safe_unescape (ca,   &ca_free);
	cert = nm_utils_str_utf8safe_unescape (cert, &cert_free);
	key  = nm_utils_str_utf8safe_unescape (key,  &key_free);

	if (   nmovpn_arg_is_set (ca)
	    && !is_pkcs12 (ca))
		args_add_strv (args, "--ca", ca);

	if (nmovpn_arg_is_set (cert) && is_pkcs12 (cert))
		args_add_strv (args, "--pkcs12", cert);
	else {
		if (nmovpn_arg_is_set (cert))
			args_add_strv (args, "--cert", cert);
		if (nmovpn_arg_is_set (key))
			args_add_strv (args, "--key", key);
	}
}

/*****************************************************************************/

static gboolean
validate_address (const char *address)
{
	const char *p = address;

	if (!address || !address[0])
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	const ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (nm_streq (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		const ValidProperty *prop = &info->table[i];
		long int tmp;

		if (!nm_streq (prop->name, key))
			continue;

		switch (prop->type) {
		case G_TYPE_STRING:
			if (!prop->address || validate_address (value))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid address “%s”"),
			             key);
			break;
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop->int_min && tmp <= prop->int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property “%s” or out of range [%d -> %d]"),
			             key, prop->int_min, prop->int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (NM_IN_STRSET (value, "yes", "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             /* Translators: keep "yes" and "no" untranslated! */
			             _("invalid boolean property “%s” (needs to be yes or no, not true or false)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property “%s” type %s"),
			             key, g_type_name (prop->type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property “%s” invalid or not supported"),
		             key);
	}
}

static gboolean
nm_openvpn_properties_validate (NMSettingVpn *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_properties[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("No VPN configuration options."));
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

static gboolean
nm_openvpn_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_secrets[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (validate_error) {
		g_propagate_error (error, validate_error);
		return FALSE;
	}
	return TRUE;
}

/*****************************************************************************/

static const char *
openvpn_binary_find_exepath (void)
{
	static const char *paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		"/usr/local/sbin/openvpn",
	};
	int i;

	for (i = 0; i < G_N_ELEMENTS (paths); i++) {
		if (g_file_test (paths[i], G_FILE_TEST_EXISTS))
			return paths[i];
	}
	return NULL;
}

static OpenvpnBinaryVersion
openvpn_binary_detect_version (const char *exepath)
{
	gs_free char *s_stdout = NULL;
	const char *s;
	int exit_code;
	int n;

	g_return_val_if_fail (exepath && exepath[0] == '/', OPENVPN_BINARY_VERSION_UNKNOWN);

	if (!g_spawn_sync (NULL,
	                   (char *[]) { (char *) exepath, "--version", NULL },
	                   NULL,
	                   G_SPAWN_STDERR_TO_DEV_NULL,
	                   NULL,
	                   NULL,
	                   &s_stdout,
	                   NULL,
	                   &exit_code,
	                   NULL))
		return OPENVPN_BINARY_VERSION_UNKNOWN;

	if (   !WIFEXITED (exit_code)
	    || !NM_IN_SET(WEXITSTATUS (exit_code), 0, 1)) {
		/* expect return code 1 (OPENVPN_EXIT_STATUS_USAGE).
		 * Since 2.5.0, it returns 0. */
		return OPENVPN_BINARY_VERSION_UNKNOWN;
	}

	/* the output for --version starts with title_string, which starts with PACKAGE_STRING,
	 * which looks like "OpenVPN 2.#...". Do a strict parsing here... */
	if (   !s_stdout
	    || !g_str_has_prefix (s_stdout, "OpenVPN 2."))
		return OPENVPN_BINARY_VERSION_UNKNOWN;
	s = &s_stdout[NM_STRLEN ("OpenVPN 2.")];

	if (!g_ascii_isdigit (s[0]))
		return OPENVPN_BINARY_VERSION_UNKNOWN;

	n = 0;
	do {
		if (n > G_MAXINT / 100)
			return OPENVPN_BINARY_VERSION_UNKNOWN;
		n = (n * 10) + (s[0] - '0');
	} while (g_ascii_isdigit ((++s)[0]));

	if (n <= 3)
		return OPENVPN_BINARY_VERSION_2_3_OR_OLDER;
	return OPENVPN_BINARY_VERSION_2_4_OR_NEWER;
}

static OpenvpnBinaryVersion
openvpn_binary_detect_version_cached (const char *exepath, OpenvpnBinaryVersion *cached)
{
	if (G_UNLIKELY (*cached == OPENVPN_BINARY_VERSION_INVALID)) {
		const char *str;

		*cached = openvpn_binary_detect_version (exepath);
		switch (*cached) {
		case OPENVPN_BINARY_VERSION_2_3_OR_OLDER:
			str = "2.3 or older";
			break;
		case OPENVPN_BINARY_VERSION_2_4_OR_NEWER:
			str = "2.4 or newer";
			break;
		default:
			str = "unknown";
			break;
		}
		_LOGI ("detected openvpn version %s", str);
	}
	return *cached;
}

/*****************************************************************************/

static void
pids_pending_data_free (PidsPendingData *pid_data)
{
	nm_clear_g_source (&pid_data->watch_id);
	nm_clear_g_source (&pid_data->kill_id);
	if (pid_data->plugin)
		g_object_remove_weak_pointer ((GObject *) pid_data->plugin, (gpointer *) &pid_data->plugin);
	g_slice_free (PidsPendingData, pid_data);
}

static PidsPendingData *
pids_pending_get (GPid pid)
{
	GSList *iter;

	for (iter = gl.pids_pending_list; iter; iter = iter->next) {
		if (((PidsPendingData *) iter->data)->pid == pid)
			return iter->data;
	}
	g_return_val_if_reached (NULL);
}

static void openvpn_child_terminated (NMOpenvpnPlugin *plugin, GPid pid, gint status);

static void
pids_pending_child_watch_cb (GPid pid, gint status, gpointer user_data)
{
	PidsPendingData *pid_data = user_data;
	NMOpenvpnPlugin *plugin;

	if (WIFEXITED (status)) {
		int exit_status;

		exit_status = WEXITSTATUS (status);
		if (exit_status != 0)
			_LOGW ("openvpn[%ld] exited with error code %d", (long) pid, exit_status);
		else
			_LOGI ("openvpn[%ld] exited with success", (long) pid);
	}
	else if (WIFSTOPPED (status))
		_LOGW ("openvpn[%ld] stopped unexpectedly with signal %d", (long) pid, WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("openvpn[%ld] died with signal %d", (long) pid, WTERMSIG (status));
	else
		_LOGW ("openvpn[%ld] died from an unnatural cause", (long) pid);

	g_return_if_fail (pid_data);
	g_return_if_fail (pid_data->pid == pid);
	g_return_if_fail (g_slist_find (gl.pids_pending_list, pid_data));

	plugin = pid_data->plugin;

	pid_data->watch_id = 0;
	gl.pids_pending_list = g_slist_remove (gl.pids_pending_list , pid_data);
	pids_pending_data_free (pid_data);

	if (plugin)
		openvpn_child_terminated (plugin, pid, status);
}

static void
pids_pending_add (GPid pid, NMOpenvpnPlugin *plugin)
{
	PidsPendingData *pid_data;

	g_return_if_fail (NM_IS_OPENVPN_PLUGIN (plugin));
	g_return_if_fail (pid > 0);

	_LOGI ("openvpn[%ld] started", (long) pid);

	pid_data = g_slice_new0 (PidsPendingData);
	pid_data->pid = pid;
	pid_data->watch_id = g_child_watch_add (pid, pids_pending_child_watch_cb, pid_data);
	pid_data->plugin = plugin;
	g_object_add_weak_pointer ((GObject *) plugin, (gpointer *) &pid_data->plugin);

	gl.pids_pending_list = g_slist_prepend (gl.pids_pending_list, pid_data);
}

static gboolean
pids_pending_ensure_killed (gpointer user_data)
{
	PidsPendingData *pid_data = user_data;

	g_return_val_if_fail (pid_data && pid_data == pids_pending_get (pid_data->pid), FALSE);

	_LOGI ("openvpn[%ld]: send SIGKILL", (long) pid_data->pid);

	pid_data->kill_id = 0;
	kill (pid_data->pid, SIGKILL);
	return FALSE;
}

static void
pids_pending_send_sigterm (PidsPendingData *pid_data)
{
	g_return_if_fail (pid_data);
	nm_assert (pid_data == pids_pending_get (pid_data->pid));

	if (pid_data->is_terminating) {
		/* we already send a SIGTERM (maybe even SIGKILL). No need to
		 * do anything further, just wait for the process to exit. */
		return;
	}

	_LOGI ("openvpn[%ld]: send SIGTERM", (long) pid_data->pid);
	pid_data->is_terminating = TRUE;
	kill (pid_data->pid, SIGTERM);
	pid_data->kill_id = g_timeout_add (2000, pids_pending_ensure_killed, pid_data);
}

static gboolean
_pids_pending_wait_for_processes_timeout (gpointer user_data)
{
	*((gboolean *) user_data) = TRUE;

	/* G_SOURCE_CONTINUE, because we have no convenient way to clear
	 * the current source-id. Let the caller cancel the timeout. */
	return G_SOURCE_CONTINUE;
}

static void
pids_pending_wait_for_processes (void)
{
	GSList *iter;
	gboolean timed_out = FALSE;
	guint source_id;

	if (!gl.pids_pending_list)
		return;

	_LOGI ("wait for %u openvpn processes to terminate...", g_slist_length (gl.pids_pending_list));
	for (iter = gl.pids_pending_list; iter; iter = iter->next)
		pids_pending_send_sigterm (iter->data);

	source_id = g_timeout_add (3000, _pids_pending_wait_for_processes_timeout, &timed_out);

	do {
		g_main_context_iteration (NULL, TRUE);
	} while (!timed_out && gl.pids_pending_list);

	nm_clear_g_source (&source_id);

	while (gl.pids_pending_list) {
		PidsPendingData *pid_data = gl.pids_pending_list->data;

		_LOGW ("openvpn[%ld]: didn't terminate in time", (long) pid_data->pid);
		gl.pids_pending_list = g_slist_delete_link (gl.pids_pending_list, gl.pids_pending_list);
		pids_pending_data_free (pid_data);
	}
}

/*****************************************************************************/

static void
nm_openvpn_disconnect_management_socket (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMOpenvpnPluginIOData *io_data = priv->io_data;

	/* This should not throw a warning since this can happen in
	   non-password modes */
	if (!io_data)
		return;

	if (io_data->socket_channel_eventid)
		g_source_remove (io_data->socket_channel_eventid);
	if (io_data->socket_channel) {
		g_io_channel_shutdown (io_data->socket_channel, FALSE, NULL);
		g_io_channel_unref (io_data->socket_channel);
	}

	g_free (io_data->username);
	g_free (io_data->proxy_username);
	g_free (io_data->pending_auth);

	if (io_data->password)
		memset (io_data->password, 0, strlen (io_data->password));
	g_free (io_data->password);

	if (io_data->priv_key_pass)
		memset (io_data->priv_key_pass, 0, strlen (io_data->priv_key_pass));
	g_free (io_data->priv_key_pass);

	if (io_data->proxy_password)
		memset (io_data->proxy_password, 0, strlen (io_data->proxy_password));
	g_free (io_data->proxy_password);
	g_free (io_data->challenge_state_id);
	g_free (io_data->challenge_text);

	g_free (priv->io_data);
	priv->io_data = NULL;
}

static char *
ovpn_quote_string (const char *unquoted)
{
	char *quoted = NULL, *q;
	char *u = (char *) unquoted;

	g_return_val_if_fail (unquoted != NULL, NULL);

	/* FIXME: use unpaged memory */
	quoted = q = g_malloc0 (strlen (unquoted) * 2);
	while (*u) {
		/* Escape certain characters */
		if (*u == ' ' || *u == '\\' || *u == '"')
			*q++ = '\\';
		*q++ = *u++;
	}

	return quoted;
}

static char *
get_detail (const char *input, const char *prefix)
{
	const char *end;

	nm_assert (prefix);

	if (!g_str_has_prefix (input, prefix))
		return NULL;

	/* Grab characters until the next ' */
	input += strlen (prefix);
	end = strchr (input, '\'');
	if (end)
		return g_strndup (input, end - input);
	return NULL;
}

/* Parse challenge response protocol message of the form
 * CRV1:flags:state_id:username:text
 */
static gboolean
parse_challenge (const char *failure_reason, char **challenge_state_id, char **challenge_text)
{
	const char *colon[4];

	if (   !failure_reason
	    || !g_str_has_prefix (failure_reason, "CRV1:"))
		return FALSE;

	colon[0] = strchr (failure_reason, ':');
	if (!colon[0])
		return FALSE;

	colon[1] = strchr (colon[0] + 1, ':');
	if (!colon[1])
		return FALSE;

	colon[2] = strchr (colon[1] + 1, ':');
	if (!colon[2])
		return FALSE;

	colon[3] = strchr (colon[2] + 1, ':');
	if (!colon[3])
		return FALSE;

	*challenge_state_id = g_strndup (colon[1] + 1, colon[2] - colon[1] - 1);
	*challenge_text = g_strdup (colon[3] + 1);
	return TRUE;
}

static void
write_user_pass (GIOChannel *channel,
                 const char *authtype,
                 const char *user,
                 const char *pass)
{
	char *quser, *qpass, *buf;

	/* Quote strings passed back to openvpn */
	quser = ovpn_quote_string (user);
	qpass = ovpn_quote_string (pass);
	buf = g_strdup_printf ("username \"%s\" \"%s\"\n"
	                       "password \"%s\" \"%s\"\n",
	                       authtype, quser,
	                       authtype, qpass);
	memset (qpass, 0, strlen (qpass));
	g_free (qpass);
	g_free (quser);

	/* Will always write everything in blocking channels (on success) */
	g_io_channel_write_chars (channel, buf, strlen (buf), NULL, NULL);
	g_io_channel_flush (channel, NULL);

	memset (buf, 0, strlen (buf));
	g_free (buf);
}

static gboolean
handle_auth (NMOpenvpnPluginIOData *io_data,
             const char *requested_auth,
             const char **out_message,
             const char ***out_hints)
{
	gboolean handled = FALSE;
	guint i = 0;
	gs_free const char **hints = NULL;

	g_return_val_if_fail (requested_auth, FALSE);
	g_return_val_if_fail (out_message && !*out_message, FALSE);
	g_return_val_if_fail (out_hints && !*out_hints, FALSE);

	if (nm_streq (requested_auth, "Auth")) {
		const char *username = io_data->username;

		/* Fall back to the default username if it wasn't overridden by the user */
		if (!username)
			username = io_data->default_username;

		if (username != NULL && io_data->password != NULL && io_data->challenge_state_id) {
			gs_free char *response = NULL;

			response = g_strdup_printf ("CRV1::%s::%s",
			                            io_data->challenge_state_id,
			                            io_data->password);
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 username,
			                 response);
			nm_clear_g_free (&io_data->challenge_state_id);
			nm_clear_g_free (&io_data->challenge_text);
		} else if (username != NULL && io_data->password != NULL) {
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 username,
			                 io_data->password);
		} else {
			hints = g_new0 (const char *, 3);
			if (!username) {
				hints[i++] = NM_OPENVPN_KEY_USERNAME;
				*out_message = _("A username is required.");
			}
			if (!io_data->password) {
				hints[i++] = NM_OPENVPN_KEY_PASSWORD;
				*out_message = _("A password is required.");
			}
			if (!username && !io_data->password)
				*out_message = _("A username and password are required.");
			if (io_data->challenge_text)
				*out_message = io_data->challenge_text;
		}
		handled = TRUE;
	} else if (nm_streq (requested_auth, "Private Key")) {
		if (io_data->priv_key_pass) {
			char *qpass, *buf;

			/* Quote strings passed back to openvpn */
			qpass = ovpn_quote_string (io_data->priv_key_pass);
			buf = g_strdup_printf ("password \"%s\" \"%s\"\n", requested_auth, qpass);
			memset (qpass, 0, strlen (qpass));
			g_free (qpass);

			/* Will always write everything in blocking channels (on success) */
			g_io_channel_write_chars (io_data->socket_channel, buf, strlen (buf), NULL, NULL);
			g_io_channel_flush (io_data->socket_channel, NULL);
			g_free (buf);
		} else {
			hints = g_new0 (const char *, 2);
			hints[i++] = NM_OPENVPN_KEY_CERTPASS;
			*out_message = _("A private key password is required.");
		}
		handled = TRUE;
	} else if (nm_streq (requested_auth, "HTTP Proxy")) {
		if (io_data->proxy_username != NULL && io_data->proxy_password != NULL) {
			write_user_pass (io_data->socket_channel,
			                 requested_auth,
			                 io_data->proxy_username,
			                 io_data->proxy_password);
		} else {
			hints = g_new0 (const char *, 3);
			if (!io_data->proxy_username) {
				hints[i++] = NM_OPENVPN_KEY_HTTP_PROXY_USERNAME;
				*out_message = _("An HTTP Proxy username is required.");
			}
			if (!io_data->proxy_password) {
				hints[i++] = NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD;
				*out_message = _("An HTTP Proxy password is required.");
			}
			if (!io_data->proxy_username && !io_data->proxy_password)
				*out_message = _("An HTTP Proxy username and password are required.");
		}
		handled = TRUE;
	}

	*out_hints = g_steal_pointer (&hints);
	return handled;
}

static void
_request_secrets (NMOpenvpnPlugin *plugin,
                  const char *message,
                  const char *const* hints)
{
	gs_free char *joined = NULL;

	_LOGD ("Requesting new secrets: '%s', %s%s%s", message,
	        NM_PRINT_FMT_QUOTED (hints, "(", (joined = g_strjoinv (",", (char **) hints)), ")", "no hints"));
	nm_vpn_service_plugin_secrets_required ((NMVpnServicePlugin *) plugin, message, (const char **) hints);
}

static gboolean
handle_management_socket (NMOpenvpnPlugin *plugin,
                          GIOChannel *source,
                          GIOCondition condition,
                          NMVpnPluginFailure *out_failure)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	gboolean again = TRUE;
	char *str = NULL;
	char *auth;
	const char *message = NULL;

	g_assert (out_failure);

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		return TRUE;

	if (!str[0]) {
		g_free (str);
		return TRUE;
	}

	_LOGD ("VPN request '%s'", str);

	auth = get_detail (str, ">PASSWORD:Need '");
	if (auth) {
		gs_free const char **hints = NULL;

		if (priv->io_data->pending_auth)
			g_free (priv->io_data->pending_auth);
		priv->io_data->pending_auth = auth;

		if (handle_auth (priv->io_data, auth, &message, &hints)) {
			/* Request new secrets if we need any */
			if (message) {
				if (priv->interactive)
					_request_secrets (plugin, message, hints);
				else {
					/* Interactive not allowed, can't ask for more secrets */
					_LOGW ("More secrets required but cannot ask interactively");
					*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
					again = FALSE;
				}
			}
		} else {
			_LOGW ("Unhandled management socket request '%s'", auth);
			*out_failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
			again = FALSE;
		}
		goto out;
	}

	auth = get_detail (str, ">PASSWORD:Verification Failed: '");
	if (auth) {
		gboolean fail = TRUE;

		if (nm_streq (auth, "Auth")) {
			gs_free char *failure_reason = NULL;

			failure_reason = get_detail (str, ">PASSWORD:Verification Failed: 'Auth' ['");
			if (parse_challenge (failure_reason, &priv->io_data->challenge_state_id, &priv->io_data->challenge_text)) {
				_LOGD ("Received challenge '%s' for state '%s'",
				       priv->io_data->challenge_state_id,
				       priv->io_data->challenge_text);
			} else
				_LOGW ("Password verification failed");

			if (priv->interactive) {
				/* Clear existing password in interactive mode, openvpn
				 * will request a new one after restarting.
				 */
				if (priv->io_data->password)
					memset (priv->io_data->password, 0, strlen (priv->io_data->password));
				g_clear_pointer (&priv->io_data->password, g_free);
				fail = FALSE;
			}
		} else if (nm_streq (auth, "Private Key"))
			_LOGW ("Private key verification failed");
		else
			_LOGW ("Unknown verification failed: %s", auth);

		if (fail) {
			*out_failure = NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED;
			again = FALSE;
		}

		g_free (auth);
	}

out:
	g_free (str);
	return again;
}

static gboolean
nm_openvpn_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (user_data);
	NMVpnPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;

	if (!handle_management_socket (plugin, source, condition, &failure)) {
		nm_vpn_service_plugin_failure ((NMVpnServicePlugin *) plugin, failure);
		return FALSE;
	}

	return TRUE;
}

static gboolean
nm_openvpn_connect_timer_cb (gpointer data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (data);
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMOpenvpnPluginIOData *io_data = priv->io_data;
	struct sockaddr_un remote = { 0 };
	int fd;

	priv->connect_count++;

	/* open socket and start listener */
	fd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		_LOGW ("Could not create management socket");
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		goto out;
	}

	remote.sun_family = AF_UNIX;
	g_strlcpy (remote.sun_path, priv->mgt_path, sizeof (remote.sun_path));
	if (connect (fd, (struct sockaddr *) &remote, sizeof (remote)) != 0) {
		close (fd);
		if (priv->connect_count <= 30)
			return G_SOURCE_CONTINUE;

		priv->connect_timer = 0;

		_LOGW ("Could not open management socket");
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	} else {
		io_data->socket_channel = g_io_channel_unix_new (fd);
		g_io_channel_set_encoding (io_data->socket_channel, NULL, NULL);
		io_data->socket_channel_eventid = g_io_add_watch (io_data->socket_channel,
		                                                  G_IO_IN,
		                                                  nm_openvpn_socket_data_cb,
		                                                  plugin);
	}

out:
	priv->connect_timer = 0;
	return G_SOURCE_REMOVE;
}

static void
nm_openvpn_schedule_connect_timer (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (200, nm_openvpn_connect_timer_cb, plugin);
}

static void
openvpn_child_terminated (NMOpenvpnPlugin *plugin, GPid pid, gint status)
{
	NMOpenvpnPluginPrivate *priv;
	NMVpnPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	gboolean good_exit = FALSE;

	g_return_if_fail (NM_IS_OPENVPN_PLUGIN (plugin));

	priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	/* Reap child if needed. */
	if (priv->pid != pid) {
		/* the dead child is not the currently active process. Nothing to do, we just
		 * reaped the PID. */
		return;
	}

	priv->pid = 0;

	/* OpenVPN doesn't supply useful exit codes :( */
	if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
		good_exit = TRUE;

	/* Try to get the last bits of data from openvpn */
	if (priv->io_data && priv->io_data->socket_channel) {
		GIOChannel *channel = priv->io_data->socket_channel;
		GIOCondition condition;

		while ((condition = g_io_channel_get_buffer_condition (channel)) & G_IO_IN) {
			if (!handle_management_socket (plugin, channel, condition, &failure)) {
				good_exit = FALSE;
				break;
			}
		}
	}

	if (good_exit)
		nm_vpn_service_plugin_disconnect ((NMVpnServicePlugin *) plugin, NULL);
	else
		nm_vpn_service_plugin_failure ((NMVpnServicePlugin *) plugin, failure);
}

/*****************************************************************************/

static void
update_io_data_from_vpn_setting (NMOpenvpnPluginIOData *io_data,
                                 NMSettingVpn *s_vpn,
                                 const char *default_username)
{
	if (default_username) {
		g_free (io_data->default_username);
		io_data->default_username = g_strdup (default_username);
	}

	g_free (io_data->username);
	io_data->username = g_strdup (nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_USERNAME));

	if (io_data->password) {
		memset (io_data->password, 0, strlen (io_data->password));
		g_free (io_data->password);
	}
	io_data->password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD));

	if (io_data->priv_key_pass) {
		memset (io_data->priv_key_pass, 0, strlen (io_data->priv_key_pass));
		g_free (io_data->priv_key_pass);
	}
	io_data->priv_key_pass = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS));

	g_free (io_data->proxy_username);
	io_data->proxy_username = g_strdup (nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME));

	if (io_data->proxy_password) {
		memset (io_data->proxy_password, 0, strlen (io_data->proxy_password));
		g_free (io_data->proxy_password);
	}
	io_data->proxy_password = g_strdup (nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD));
}

static char *
mgt_path_create (NMConnection *connection, GError **error)
{
	int errsv;

	/* Setup runtime directory */
	if (g_mkdir_with_parents (RUNDIR, 0755) != 0) {
		errsv = errno;
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Cannot create run-dir %s (%s)",
		             RUNDIR, g_strerror (errsv));
		return NULL;
	}

	return g_strdup_printf (RUNDIR"/nm-openvpn-%s",
	                        nm_connection_get_uuid (connection));
}

#define MAX_GROUPS 128
static gboolean
is_dir_writable (const char *dir, const char *user)
{
	struct stat sb;
	struct passwd *pw;

	if (stat (dir, &sb) == -1)
		return FALSE;
	pw = getpwnam (user);
	if (!pw)
		return FALSE;

	if (pw->pw_uid == 0)
		return TRUE;

	if (sb.st_mode & S_IWOTH)
		return TRUE;
	else if (sb.st_mode & S_IWGRP) {
		/* Group has write access. Is user in that group? */
		int i, ngroups = MAX_GROUPS;
		gid_t groups[MAX_GROUPS];

		getgrouplist (user, pw->pw_gid, groups, &ngroups);
		for (i = 0; i < ngroups && i < MAX_GROUPS; i++) {
			if (groups[i] == sb.st_gid)
				return TRUE;
		}
	} else if (sb.st_mode & S_IWUSR) {
		/* The owner has write access. Does the user own the file? */
		if (pw->pw_uid == sb.st_uid)
			return TRUE;
	}
	return FALSE;
}

/* Check existence of 'tmp' directory inside @chdir
 * and write access in @chdir and @chdir/tmp for @user.
 */
static gboolean
check_chroot_dir_usability (const char *chdir, const char *user)
{
	char *tmp_dir;
	gboolean b1, b2;

	tmp_dir = g_strdup_printf ("%s/tmp", chdir);
	if (!g_file_test (tmp_dir, G_FILE_TEST_IS_DIR)) {
		g_free (tmp_dir);
		return FALSE;
	}

	b1 = is_dir_writable (chdir, user);
	b2 = is_dir_writable (tmp_dir, user);
	g_free (tmp_dir);
	return b1 && b2;
}

static gboolean
nm_openvpn_start_openvpn_binary (NMOpenvpnPlugin *plugin,
                                 NMConnection *connection,
                                 GError **error)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	const char *openvpn_binary, *tmp, *tmp2, *tmp3, *tmp4;
	gs_unref_ptrarray GPtrArray *args = NULL;
	GPid pid;
	gboolean dev_type_is_tap;
	const char *defport, *proto_tcp;
	const char *compress;
	const char *tls_remote = NULL;
	const char *nm_openvpn_user, *nm_openvpn_group, *nm_openvpn_chroot;
	gs_free char *bus_name = NULL;
	NMSettingVpn *s_vpn;
	const char *connection_type;
	gint64 v_int64;
	OpenvpnBinaryVersion openvpn_binary_version = OPENVPN_BINARY_VERSION_INVALID;
	guint num_remotes = 0;
	gs_free char *cmd_log = NULL;
	NMOvpnComp comp;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (!validate_connection_type (connection_type)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Invalid connection type."));
		return FALSE;
	}

	/* Validate the properties */
	if (!nm_openvpn_properties_validate (s_vpn, error))
		return FALSE;

	/* Validate secrets */
	if (!nm_openvpn_secrets_validate (s_vpn, error))
		return FALSE;

	/* Find openvpn */
	openvpn_binary = openvpn_binary_find_exepath ();
	if (!openvpn_binary) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Could not find the openvpn binary."));
		return FALSE;
	}

	args = g_ptr_array_new_with_free_func (g_free);

	args_add_strv (args, openvpn_binary);

	defport = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PORT);
	if (!nmovpn_arg_is_set (defport))
		defport = NULL;

	proto_tcp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROTO_TCP);
	if (!nmovpn_arg_is_set (proto_tcp))
		proto_tcp = NULL;

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE);
	if (tmp && *tmp) {
		gs_free char *tmp_clone = NULL;
		char *tmp_remaining;
		const char *tok;

		tmp_remaining = tmp_clone = g_strdup (tmp);
		while ((tok = strsep (&tmp_remaining, " \t,")) != NULL) {
			gs_free char *str_free = NULL;
			const char *host, *port, *proto;
			gssize eidx;

			eidx = nmovpn_remote_parse (tok,
			                            &str_free,
			                            &host,
			                            &port,
			                            &proto,
			                            NULL);
			if (eidx >= 0)
				continue;

			num_remotes++;
			args_add_strv (args, "--remote", host);

			if (port) {
				if (!args_add_numstr (args, port))
					nm_assert_not_reached ();
			} else if (defport) {
				if (!args_add_numstr (args, defport)) {
					g_set_error (error,
					             NM_VPN_PLUGIN_ERROR,
					             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					             _("Invalid port number “%s”."),
					             defport);
					return FALSE;
				}
			} else
				args_add_strv (args, "1194"); /* default IANA port */

			if (proto) {
				if (nm_streq (proto, "tcp"))
					args_add_strv (args, "tcp-client");
				else if (nm_streq (proto, "tcp4"))
					args_add_strv (args, "tcp4-client");
				else if (nm_streq (proto, "tcp6"))
					args_add_strv (args, "tcp6-client");
				else if (NM_IN_STRSET (proto, NMOVPN_PROTCOL_TYPES))
					args_add_strv (args, proto);
				else {
					g_set_error (error,
					             NM_VPN_PLUGIN_ERROR,
					             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					             _("Invalid proto “%s”."), proto);
					return FALSE;
				}
			} else if (nm_streq0 (proto_tcp, "yes"))
				args_add_strv (args, "tcp-client");
			else {
				args_add_strv (args, "udp");
				args_add_strv (args, "--explicit-exit-notify");
			}
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--remote-random");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_RANDOM_HOSTNAME);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--remote-random-hostname");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_ALLOW_PULL_FQDN);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--allow-pull-fqdn");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUN_IPV6);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--tun-ipv6");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_TYPE);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_SERVER);
	tmp3 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_PORT);
	tmp4 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PROXY_RETRY);
	if (   nmovpn_arg_is_set (tmp)
	    && nmovpn_arg_is_set (tmp2)) {
		if (nm_streq (tmp, "http")) {
			args_add_strv0 (args, "--http-proxy",
			                      tmp2,
			                      tmp3 ?: "8080",
			                      "auto",  /* Automatic proxy auth method detection */
			                      tmp4 ? "--http-proxy-retry" : NULL);
		} else if (nm_streq (tmp, "socks")) {
			args_add_strv0 (args, "--socks-proxy",
			                      tmp2,
			                      tmp3 ?: "1080",
			                      tmp4 ? "--socks-proxy-retry" : NULL);
		} else {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			              _("Invalid proxy type “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* openvpn understands 4 different modes for --comp-lzo, which have
	 * different meaning:
	 *  1) no --comp-lzo option
	 *  2) --comp-lzo yes
	 *  3) --comp-lzo [adaptive]
	 *  4) --comp-lzo no
	 *
	 * In the past, nm-openvpn only supported 1) and 2) by having no
	 * comp-lzo connection setting or "comp-lzo=yes", respectively.
	 *
	 * However, old plasma-nm would set "comp-lzo=no" in the connection
	 * to mean 1). Thus, "comp-lzo=no" is spoiled to mean 4) in order
	 * to preserve backward compatibily.
	 * We use instead a special value "no-by-default" to express "no".
	 *
	 * See bgo#769177
	 */

	/* New (2.4+) compress option ("lz4", "lzo", ...) */
	compress = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_COMPRESS);
	/* Legacy option ("yes", "adaptive", "no", ...) */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_COMP_LZO);

	if (compress && tmp)
		_LOGW ("'compress' option overrides 'comp-lzo'");

	comp = nmovpn_compression_from_options (tmp, compress);
	openvpn_binary_detect_version_cached (openvpn_binary, &openvpn_binary_version);

	switch (comp) {
	case NMOVPN_COMP_DISABLED:
		break;
	case NMOVPN_COMP_LZO:
		if (openvpn_binary_version == OPENVPN_BINARY_VERSION_2_3_OR_OLDER)
			args_add_strv (args, "--comp-lzo", "yes");
		else
			args_add_strv (args, "--compress", "lzo");
		break;
	case NMOVPN_COMP_LZ4:
	case NMOVPN_COMP_LZ4_V2:
	case NMOVPN_COMP_AUTO:
		if (openvpn_binary_version == OPENVPN_BINARY_VERSION_2_3_OR_OLDER)
			_LOGW ("\"compress\" option supported only by OpenVPN >= 2.4");

		if (comp == NMOVPN_COMP_LZ4)
			args_add_strv (args, "--compress", "lz4");
		else if (comp == NMOVPN_COMP_LZ4_V2)
			args_add_strv (args, "--compress", "lz4-v2");
		else
			args_add_strv (args, "--compress");
		break;
	case NMOVPN_COMP_LEGACY_LZO_DISABLED:
	case NMOVPN_COMP_LEGACY_LZO_ADAPTIVE:
		if (openvpn_binary_version != OPENVPN_BINARY_VERSION_2_3_OR_OLDER)
			_LOGW ("\"comp-lzo\" is deprecated and will be removed in future OpenVPN releases");

		args_add_strv (args, "--comp-lzo",
		                  comp == NMOVPN_COMP_LEGACY_LZO_DISABLED
		               ? "no"
		               : "adaptive");
		break;
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FLOAT);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--float");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_NCP_DISABLE);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--ncp-disable");

	/* ping, ping-exit, ping-restart */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING);
	if (tmp) {
		args_add_strv (args, "--ping");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_EXIT);
	if (tmp) {
		args_add_strv (args, "--ping-exit");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping-exit duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PING_RESTART);
	if (tmp) {
		args_add_strv (args, "--ping-restart");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid ping-restart duration “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECT_TIMEOUT);
	if (tmp) {
		args_add_strv (args, "--connect-timeout");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid connect timeout “%s”."),
			             tmp);
			return FALSE;
		}
	} else if (num_remotes > 1) {
		/* NM waits at most 60 seconds: lower the connect timeout if
		 * there are multiple remotes, so that we try at least 3 of them.
		 */
		args_add_strv (args, "--connect-timeout");
		args_add_int64 (args, NM_MAX (60 / num_remotes, 20U));
	}

	args_add_strv (args, "--nobind");

	/* max routes allowed from openvpn server */
	tmp = nm_setting_vpn_get_data_item(s_vpn, NM_OPENVPN_KEY_MAX_ROUTES);
	if (tmp) {
		/* max-routes option is deprecated in 2.4 release
		 * https://github.com/OpenVPN/openvpn/commit/d0085293e709c8a722356cfa68ad74c962aef9a2
		 */
		args_add_strv (args, "--max-routes");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid max-routes argument “%s”."),
			             tmp);
			return FALSE;
		}
	}

	/* Device and device type, defaults to tun */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_DEV_TYPE);
	tmp3 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TAP_DEV);
	args_add_strv (args, "--dev");
	if (tmp) {
		const char *tmp_unescaped;

		tmp_unescaped = args_add_utf8safe_str (args, tmp);
		dev_type_is_tap = g_str_has_prefix (tmp_unescaped, "tap");
	} else if (tmp2) {
		args_add_strv (args, tmp2);
		dev_type_is_tap = FALSE; /* will be reset below (avoid maybe-uninitialized warning) */
	} else if (nm_streq0 (tmp3, "yes")) {
		args_add_strv (args, "tap");
		dev_type_is_tap = TRUE;
	} else {
		args_add_strv (args, "tun");
		dev_type_is_tap = FALSE;
	}

	/* Add '--dev-type' if the type was explicitly set */
	if (tmp2) {
		args_add_strv (args, "--dev-type", tmp2);
		dev_type_is_tap = nm_streq (tmp2, "tap");
	}

	args_add_vpn_data (args, s_vpn, NM_OPENVPN_KEY_CIPHER, "--cipher");

	args_add_vpn_data (args, s_vpn, NM_OPENVPN_KEY_TLS_CIPHER, "--tls-cipher");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEYSIZE);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--keysize");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid keysize “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_AUTH);
	if (tmp)
		args_add_strv (args, "--auth", tmp);

	args_add_strv (args, "--auth-nocache");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tls-auth");
		args_add_utf8safe_str (args, tmp);
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TA_DIR);
		if (nmovpn_arg_is_set (tmp))
			args_add_strv (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tls-crypt");
		args_add_utf8safe_str (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_CRYPT_V2);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tls-crypt-v2");
		args_add_utf8safe_str (args, tmp);
	}
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MIN);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tls-version-min");
		args_add_strv (args, tmp);
	}
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_VERSION_MAX);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tls-version-max");
		args_add_strv (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_EXTRA_CERTS);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--extra-certs");
		args_add_utf8safe_str (args, tmp);
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TLS_REMOTE);
	if (nmovpn_arg_is_set (tmp)) {
		if (openvpn_binary_detect_version_cached (openvpn_binary, &openvpn_binary_version) == OPENVPN_BINARY_VERSION_2_3_OR_OLDER) {
			_LOGW ("the tls-remote option is deprecated and removed from OpenVPN 2.4. Update your connection to use verify-x509-name (for example, \"verify-x509-name=name:%s\")", tmp);
			args_add_strv (args, "--tls-remote", tmp);
		} else {
			_LOGW ("the tls-remote option is deprecated and removed from OpenVPN 2.4. For compatibility, the plugin uses \"verify-x509-name\" \"%s\" \"name\" instead. Update your connection to use for example \"verify-x509-name=name:%s\")", tmp, tmp);
			args_add_strv (args, "--verify-x509-name", tmp, "name");
		}
		tls_remote = tmp;
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_VERIFY_X509_NAME);
	if (nmovpn_arg_is_set (tmp)) {
		const char *name;
		gs_free char *type = NULL;

		if (tls_remote) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid configuration with tls-remote and verify-x509-name."));
			return FALSE;
		}

		name = strchr (tmp, ':');
		if (name) {
			type = g_strndup (tmp, name - tmp);
			name++;
		} else
			name = tmp;
		if (!name[0] || !g_utf8_validate(name, -1, NULL)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid verify-x509-name."));
			return FALSE;
		}

		args_add_strv (args, "--verify-x509-name",
		                     name,
		                     type ?: "subject");
	}

	args_add_vpn_data (args, s_vpn, NM_OPENVPN_KEY_REMOTE_CERT_TLS, "--remote-cert-tls");

	args_add_vpn_data (args, s_vpn, NM_OPENVPN_KEY_NS_CERT_TYPE, "--ns-cert-type");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_RENEG_SECONDS);
	if (!connection_type_is_tls_mode (connection_type)) {
		/* Ignore --reneg-sec option if we are not in TLS mode (as enabled
		 * by --client below). openvpn will error out otherwise, see bgo#749050. */
	} else if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--reneg-sec");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid reneg seconds “%s”."),
			             tmp);
			return FALSE;
		}
	} else {
		/* Either the server and client must agree on the renegotiation
		 * interval, or it should be disabled on one side to prevent
		 * too-frequent renegotiations, which make two-factor auth quite
		 * painful.
		 */
		args_add_strv (args, "--reneg-sec", "0");
	}

	if (gl.log_level_ovpn >= 0) {
		args_add_strv (args, "--verb");
		args_add_int64 (args, gl.log_level_ovpn);
	}

	if (gl.log_syslog) {
		args_add_strv (args, "--syslog",
		                     "nm-openvpn");
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_TUNNEL_MTU);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--tun-mtu");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid TUN MTU size “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_FRAGMENT_SIZE);
	if (nmovpn_arg_is_set (tmp)) {
		args_add_strv (args, "--fragment");
		if (!args_add_numstr (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid fragment size “%s”."),
			             tmp);
			return FALSE;
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MSSFIX);
	if (tmp) {
		if (nm_streq (tmp, "yes"))
			args_add_strv (args, "--mssfix");
		else if ((v_int64 = _nm_utils_ascii_str_to_int64 (tmp, 10, 0, G_MAXINT32, -1)) != -1) {
			args_add_strv (args, "--mssfix");
			args_add_int64 (args, v_int64);
		}
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_MTU_DISC);
	if (NM_IN_STRSET (tmp, "no", "maybe", "yes"))
		args_add_strv (args, "--mtu-disc", tmp);

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_FILE);
	if (tmp)
		args_add_strv (args, "--crl-verify", tmp);
	else {
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CRL_VERIFY_DIR);
		if (tmp)
			args_add_strv (args, "--crl-verify", tmp, "dir");
	}

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_LOCAL_IP);
	tmp2 = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_REMOTE_IP);
	if (tmp && tmp2)
		args_add_strv (args, "--ifconfig", tmp, tmp2);

	/* Punch script security in the face; this option was added to OpenVPN 2.1-rc9
	 * and defaults to disallowing any scripts, a behavior change from previous
	 * versions.
	 */
	args_add_strv (args, "--script-security", "2");

	/* Up script, called when connection has been established or has been restarted */
	g_object_get (plugin, NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, &bus_name, NULL);
	args_add_strv (args, "--up");
	args_add_str_take (args, g_strdup_printf ("%s --debug %d %ld --bus-name %s %s --",
	                                          NM_OPENVPN_HELPER_PATH,
	                                          gl.log_level,
	                                          (long) getpid(),
	                                          bus_name,
	                                          dev_type_is_tap ? "--tap" : "--tun"));

	args_add_strv (args, "--up-restart");

	/* Keep key and tun if restart is needed */
	args_add_strv (args, "--persist-key");
	args_add_strv (args, "--persist-tun");

	/* Management socket for localhost access to supply username and password */
	g_clear_pointer (&priv->mgt_path, g_free);
	priv->mgt_path = mgt_path_create (connection, error);
	if (!priv->mgt_path)
		return FALSE;
	args_add_strv (args, "--management", priv->mgt_path, "unix");
	args_add_strv (args, "--management-client-user", "root");
	args_add_strv (args, "--management-client-group", "root");

	/* Query on the management socket for user/pass */
	args_add_strv (args, "--management-query-passwords");
	args_add_strv (args, "--auth-retry", "interact");

	/* do not let openvpn setup routes or addresses, NM will handle it */
	args_add_strv (args, "--route-noexec");
	args_add_strv (args, "--ifconfig-noexec");

	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_PUSH_PEER_INFO);
	if (nm_streq0 (tmp, "yes"))
		args_add_strv (args, "--push-peer-info");

	/* Now append configuration options which are dependent on the configuration type */
	if (nm_streq (connection_type, NM_OPENVPN_CONTYPE_TLS)) {
		args_add_strv (args, "--client");
		args_add_vpn_certs (args, s_vpn);
	} else if (nm_streq (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY);
		if (nmovpn_arg_is_set (tmp)) {
			args_add_strv (args, "--secret");
			args_add_utf8safe_str (args, tmp);
			tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
			if (nmovpn_arg_is_set (tmp))
				args_add_strv (args, tmp);
		}
	} else if (nm_streq (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Client mode */
		args_add_strv (args, "--client");
		/* Use user/path authentication */
		args_add_strv (args, "--auth-user-pass");

		tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CA);
		if (nmovpn_arg_is_set (tmp)) {
			args_add_strv (args, "--ca");
			args_add_utf8safe_str (args, tmp);
		}
	} else if (nm_streq (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		args_add_strv (args, "--client");
		args_add_vpn_certs (args, s_vpn);
		/* Use user/path authentication */
		args_add_strv (args, "--auth-user-pass");
	} else {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Unknown connection type “%s”."),
		             connection_type);
		return FALSE;
	}

	/* Allow openvpn to be run as a specified user:group.
	 *
	 * We do this by default. The only way to disable it is by setting
	 * empty environment variables NM_OPENVPN_USER and NM_OPENVPN_GROUP. */
	nm_openvpn_user = getenv ("NM_OPENVPN_USER") ?: NM_OPENVPN_USER;
	nm_openvpn_group = getenv ("NM_OPENVPN_GROUP") ?: NM_OPENVPN_GROUP;
	if (*nm_openvpn_user) {
		if (getpwnam (nm_openvpn_user))
			args_add_strv (args, "--user", nm_openvpn_user);
		else {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("User “%s” not found, check NM_OPENVPN_USER."),
			             nm_openvpn_user);
			return FALSE;
		}
	}
	if (*nm_openvpn_group) {
		if (getgrnam (nm_openvpn_group))
			args_add_strv (args, "--group", nm_openvpn_group);
		else {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Group “%s” not found, check NM_OPENVPN_GROUP."),
			             nm_openvpn_group);
			return FALSE;
		}
	}

	/* we try to chroot be default. The only way to disable that is by
	 * setting the an empty environment variable NM_OPENVPN_CHROOT. */
	nm_openvpn_chroot = getenv ("NM_OPENVPN_CHROOT") ?: NM_OPENVPN_CHROOT;
	if (*nm_openvpn_chroot) {
		if (check_chroot_dir_usability (nm_openvpn_chroot, nm_openvpn_user))
			args_add_strv (args, "--chroot", nm_openvpn_chroot);
		else {
			_LOGW ("Directory '%s' not usable for chroot by '%s', openvpn will not be chrooted.",
			        nm_openvpn_chroot, nm_openvpn_user);
		}
	}

	g_ptr_array_add (args, NULL);

	_LOGD ("EXEC: '%s'", (cmd_log = g_strjoinv (" ", (char **) args->pdata)));

	if (!g_spawn_async (NULL, (char **) args->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error))
		return FALSE;

	pids_pending_add (pid, plugin);

	g_warn_if_fail (!priv->pid);
	priv->pid = pid;

	/* Listen to the management socket for a few connection types:
	   PASSWORD: Will require username and password
	   X509USERPASS: Will require username and password and maybe certificate password
	   X509: May require certificate password
	*/
	if (   NM_IN_STRSET (connection_type, NM_OPENVPN_CONTYPE_TLS,
	                                      NM_OPENVPN_CONTYPE_PASSWORD,
	                                      NM_OPENVPN_CONTYPE_PASSWORD_TLS)
	    || nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME)) {

		priv->io_data = g_malloc0 (sizeof (NMOpenvpnPluginIOData));
		update_io_data_from_vpn_setting (priv->io_data, s_vpn,
		                                 nm_setting_vpn_get_user_name (s_vpn));
		nm_openvpn_schedule_connect_timer (plugin);
	}

	return TRUE;
}

static const char *
check_need_secrets (NMSettingVpn *s_vpn, gboolean *need_secrets)
{
	const char *tmp, *key, *ctype;
	NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;
	gs_free char *key_free = NULL;

	g_return_val_if_fail (s_vpn != NULL, FALSE);
	g_return_val_if_fail (need_secrets != NULL, FALSE);

	*need_secrets = FALSE;

	ctype = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (!validate_connection_type (ctype))
		return NULL;

	if (nm_streq (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Will require a password and maybe private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS))
			*need_secrets = TRUE;

		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (nm_streq (ctype, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Will require a password */
		if (!nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_PASSWORD)) {
			*need_secrets = TRUE;
			if (nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_OPENVPN_KEY_PASSWORD, &secret_flags, NULL)) {
				if (secret_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
					*need_secrets = FALSE;
			}
		}
	} else if (nm_streq (ctype, NM_OPENVPN_CONTYPE_TLS)) {
		/* May require private key password */
		key = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_KEY);
		key = nm_utils_str_utf8safe_unescape (key, &key_free);
		if (is_encrypted (key) && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_CERTPASS))
			*need_secrets = TRUE;
	} else {
		/* Static key doesn't need passwords */
	}

	/* HTTP Proxy might require a password; assume so if there's an HTTP proxy username */
	tmp = nm_setting_vpn_get_data_item (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_USERNAME);
	if (tmp && !nm_setting_vpn_get_secret (s_vpn, NM_OPENVPN_KEY_HTTP_PROXY_PASSWORD))
		*need_secrets = TRUE;

	return ctype;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin,
                 GError **err)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->mgt_path) {
		/* openvpn does not cleanup the management socket upon exit,
		 * possibly it could not even because it changed user */
		(void) unlink (priv->mgt_path);
		g_clear_pointer (&priv->mgt_path, g_free);
	}

	if (priv->pid) {
		pids_pending_send_sigterm (pids_pending_get (priv->pid));
		priv->pid = 0;
	}

	return TRUE;
}

static gboolean
_connect_common (NMVpnServicePlugin *plugin,
                 NMConnection *connection,
                 gboolean interactive,
                 GVariant *details,
                 GError **error)
{
	GError *local = NULL;

	NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin)->interactive = interactive;

	_LOGD ("connect (interactive=%d)", interactive);

	if (!real_disconnect (plugin, &local)) {
		_LOGW ("Could not clean up previous daemon run: %s", local->message);
		g_error_free (local);
	}

	return nm_openvpn_start_openvpn_binary (NM_OPENVPN_PLUGIN (plugin),
	                                        connection,
	                                        error);
}

static gboolean
real_connect (NMVpnServicePlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	return _connect_common (plugin, connection, FALSE, NULL, error);
}

static gboolean
real_connect_interactive (NMVpnServicePlugin   *plugin,
                          NMConnection  *connection,
                          GVariant      *details,
                          GError       **error)
{
	return _connect_common (plugin, connection, TRUE, details, error);
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	const char *connection_type;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	if (_LOGD_enabled ()) {
		_LOGD ("connection -------------------------------------");
		nm_connection_dump (connection);
	}

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	connection_type = check_need_secrets (s_vpn, &need_secrets);
	if (!connection_type) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		                     _("Invalid connection type."));
		return FALSE;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
real_new_secrets (NMVpnServicePlugin *base_plugin,
                  NMConnection *connection,
                  GError **error)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (base_plugin);
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *message = NULL;
	gs_free const char **hints = NULL;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not process the request because the VPN connection settings were invalid."));
		return FALSE;
	}

	_LOGD ("VPN received new secrets; sending to management interface");

	update_io_data_from_vpn_setting (priv->io_data, s_vpn, NULL);

	g_warn_if_fail (priv->io_data->pending_auth);
	if (!handle_auth (priv->io_data, priv->io_data->pending_auth, &message, &hints)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_FAILED,
		                     _("Unhandled pending authentication."));
		return FALSE;
	}

	/* Request new secrets if we need any */
	if (message)
		_request_secrets (plugin, message, hints);
	return TRUE;
}

static void
nm_openvpn_plugin_init (NMOpenvpnPlugin *plugin)
{
}

static void
dispose (GObject *object)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (object);

	nm_clear_g_source (&priv->connect_timer);

	if (priv->pid) {
		pids_pending_send_sigterm (pids_pending_get (priv->pid));
		priv->pid = 0;
	}

	G_OBJECT_CLASS (nm_openvpn_plugin_parent_class)->dispose (object);
}

static void
nm_openvpn_plugin_class_init (NMOpenvpnPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMOpenvpnPluginPrivate));

	object_class->dispose = dispose;

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->connect_interactive = real_connect_interactive;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
	parent_class->new_secrets  = real_new_secrets;
}

static void
plugin_state_changed (NMOpenvpnPlugin *plugin,
                      NMVpnServiceState state,
                      gpointer user_data)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	switch (state) {
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		/* Cleanup on failure */
		nm_clear_g_source (&priv->connect_timer);
		nm_openvpn_disconnect_management_socket (plugin);
		break;
	default:
		break;
	}
}

NMOpenvpnPlugin *
nm_openvpn_plugin_new (const char *bus_name)
{
	NMOpenvpnPlugin *plugin;
	GError *error = NULL;

	plugin =  (NMOpenvpnPlugin *) g_initable_new (NM_TYPE_OPENVPN_PLUGIN, NULL, &error,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                                              NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                                              NULL);

	if (plugin) {
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (plugin_state_changed), NULL);
	} else {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static gboolean
signal_handler (gpointer user_data)
{
	g_main_loop_quit (user_data);
	return G_SOURCE_REMOVE;
}

static void
quit_mainloop (NMVpnServicePlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	gs_unref_object NMOpenvpnPlugin *plugin = NULL;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	gchar *bus_name = NM_DBUS_SERVICE_OPENVPN;
	GError *error = NULL;
	GMainLoop *loop;
	guint source_id_sigterm;
	guint source_id_sigint;
	gulong handler_id_plugin = 0;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	if (getenv ("OPENVPN_DEBUG"))
		gl.debug = TRUE;

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_OPENVPN_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	                              _("nm-openvpn-service provides integrated "
	                                "OpenVPN capability to NetworkManager."));

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_clear_error (&error);
		return EXIT_FAILURE;
	}
	g_option_context_free (opt_ctx);

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG, -1);
	if (gl.log_level >= 0) {
		if (gl.log_level >= LOG_DEBUG)
			gl.log_level_ovpn = 10;
		else if (gl.log_level >= LOG_INFO)
			gl.log_level_ovpn = 5;
		else if (gl.log_level > 0)
			gl.log_level_ovpn = 2;
		else
			gl.log_level_ovpn = 1;
	} else if (gl.debug)
		gl.log_level_ovpn = 10;
	else {
		/* the default level is already "--verb 1", which is fine for us. */
		gl.log_level_ovpn = -1;
	}

	if (gl.log_level < 0)
		gl.log_level = gl.debug ? LOG_INFO : LOG_NOTICE;

	gl.log_syslog = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_SYSLOG"),
	                                              10, 0, 1,
	                                              gl.debug ? 0 : 1);

	_LOGD ("nm-openvpn-service (version " DIST_VERSION ") starting...");

	if (   !g_file_test ("/sys/class/misc/tun", G_FILE_TEST_EXISTS)
	    && (system ("/sbin/modprobe tun") == -1))
		return EXIT_FAILURE;

	plugin = nm_openvpn_plugin_new (bus_name);
	if (!plugin)
		return EXIT_FAILURE;

	loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		handler_id_plugin = g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);

	signal (SIGPIPE, SIG_IGN);
	source_id_sigterm = g_unix_signal_add (SIGTERM, signal_handler, loop);
	source_id_sigint = g_unix_signal_add (SIGINT, signal_handler, loop);

	g_main_loop_run (loop);

	nm_clear_g_source (&source_id_sigterm);
	nm_clear_g_source (&source_id_sigint);
	nm_clear_g_signal_handler (plugin, &handler_id_plugin);

	g_clear_object (&plugin);

	pids_pending_wait_for_processes ();

	g_main_loop_unref (loop);
	return EXIT_SUCCESS;
}
