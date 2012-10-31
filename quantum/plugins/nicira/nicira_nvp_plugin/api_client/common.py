# Copyright (C) 2009-2012 Nicira Networks, Inc. All Rights Reserved.
#
# This software is provided only under the terms and conditions of a written
# license agreement with Nicira. If no such agreement applies to you, you are
# not authorized to use this software. Contact Nicira to obtain an appropriate
# license: www.nicira.com.

import httplib


def _conn_str(conn):
    if isinstance(conn, httplib.HTTPSConnection):
        proto = "https://"
    elif isinstance(conn, httplib.HTTPConnection):
        proto = "http://"
    else:
        raise TypeError('_conn_str() invalid connection type: %s' % type(conn))

    return "%s%s:%s" % (proto, conn.host, conn.port)
