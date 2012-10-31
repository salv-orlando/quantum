# Copyright (C) 2009-2012 Nicira Networks, Inc. All Rights Reserved.
#
# This software is provided only under the terms and conditions of a written
# license agreement with Nicira. If no such agreement applies to you, you are
# not authorized to use this software. Contact Nicira to obtain an appropriate
# license: www.nicira.com.

from abc import ABCMeta
from abc import abstractmethod
import httplib
import time
import copy
import logging
import urlparse
from common import _conn_str

lg = logging.getLogger("nvp_api_request")

# Default parameters.
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_HTTP_TIMEOUT = 10
DEFAULT_RETRIES = 2
DEFAULT_REDIRECTS = 2
DEFAULT_API_REQUEST_POOL_SIZE = 1000
DEFAULT_MAXIMUM_REQUEST_ID = 4294967295
DOWNLOAD_TIMEOUT = 180  # The UI code has a coorespoind 190 sec timeout
                        # for downloads, see: django/nvp_console/views.py


class NvpApiRequest(object):
    '''An abstract baseclass for all ApiRequest implementations.

    This defines the interface and property structure for both eventlet and
    gevent-based ApiRequest classes.
    '''

    __metaclass__ = ABCMeta

    # List of allowed status codes.
    ALLOWED_STATUS_CODES = [
        httplib.OK,
        httplib.CREATED,
        httplib.NO_CONTENT,
        httplib.MOVED_PERMANENTLY,
        httplib.TEMPORARY_REDIRECT,
        httplib.BAD_REQUEST,
        httplib.UNAUTHORIZED,
        httplib.FORBIDDEN,
        httplib.NOT_FOUND,
        httplib.CONFLICT,
        httplib.INTERNAL_SERVER_ERROR,
        httplib.SERVICE_UNAVAILABLE
    ]

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def join(self):
        pass

    @abstractmethod
    def copy(self):
        pass

    def _issue_request(self):
        '''Issue a request to a provider.'''
        conn = (self._client_conn or
                self._api_client.acquire_connection(True,
                                                    copy.copy(self._headers),
                                                    rid=self._rid()))
        if conn is None:
            error = Exception("No API connections available")
            self._request_error = error
            return error

        url = self._url
        lg.debug("[%d] Issuing - request '%s'" %
                 (self._rid(), self._request_str(conn, url)))
        issued_time = time.time()
        is_conn_error = False
        is_conn_service_unavail = False
        try:
            redirects = 0
            while (redirects <= self._redirects):
                # Update connection with user specified request timeout,
                # the connect timeout is usually smaller so we only set
                # the request timeout after a connection is established
                if conn.sock is None:
                    conn.connect()
                    conn.sock.settimeout(self._http_timeout)
                elif conn.sock.gettimeout() != self._http_timeout:
                    conn.sock.settimeout(self._http_timeout)

                headers = copy.copy(self._headers)
                cookie = self._api_client.auth_cookie(conn)
                if cookie:
                    headers["Cookie"] = cookie

                gen = self._api_client.nvp_config_gen
                if gen:
                    headers["X-Nvp-Wait-For-Config-Generation"] = gen
                    lg.debug("Setting %s request header: %s" %
                             ('X-Nvp-Wait-For-Config-Generation', gen))
                try:
                    conn.request(self._method, url, self._body, headers)
                except Exception as e:
                    lg.warn('[%d] Exception issuing request: %s' %
                            (self._rid(), e))
                    raise e

                response = conn.getresponse()
                response.body = response.read()
                response.headers = response.getheaders()
                lg.debug("[%d] Completed request '%s': %s (%0.2f seconds)"
                         % (self._rid(), self._request_str(conn, url),
                            response.status, time.time() - issued_time))

                new_gen = response.getheader('X-Nvp-Config-Generation', None)
                if new_gen:
                    lg.debug("Reading %s response header: %s" %
                             ('X-Nvp-config-Generation', new_gen))
                    if (self._api_client.nvp_config_gen is None or
                        self._api_client.nvp_config_gen < int(new_gen)):
                        self._api_client.nvp_config_gen = int(new_gen)

                if response.status == httplib.UNAUTHORIZED:

                    if cookie is None and self._url != "/ws.v1/login":
                        # The connection still has no valid cookie despite
                        # attemps to authenticate and the request has failed
                        # with unauthorized status code. If this isn't a
                        # a request to authenticate, we should abort the
                        # request since there is no point in retrying.
                        self._abort = True
                    else:
                        # If request is unauthorized, clear the session cookie
                        # for the current provider so that subsequent requests
                        # to the same provider triggers re-authentication.
                        self._api_client.set_auth_cookie(conn, None)

                    self._api_client.set_auth_cookie(conn, None)
                elif response.status == httplib.SERVICE_UNAVAILABLE:
                    is_conn_service_unavail = True

                if response.status not in [httplib.MOVED_PERMANENTLY,
                                           httplib.TEMPORARY_REDIRECT]:
                    break
                elif redirects >= self._redirects:
                    lg.info("[%d] Maximum redirects exceeded, aborting request"
                            % self._rid())
                    break
                redirects += 1

                conn, url = self._redirect_params(conn, response.headers,
                                                  self._client_conn is None)
                if url is None:
                    response.status = httplib.INTERNAL_SERVER_ERROR
                    break
                lg.info("[%d] Redirecting request to: %s" %
                        (self._rid(), self._request_str(conn, url)))

            # FIX for #9415. If we receive any of these responses, then
            # our server did not process our request and may be in an
            # errored state. Raise an exception, which will cause the
            # the conn to be released with is_conn_error == True
            # which puts the conn on the back of the client's priority
            # queue.
            if response.status >= 500:
                lg.warn("[%d] Request '%s %s' received: %s"
                        % (self._rid(), self._method, self._url,
                           response.status))
                raise Exception('Server error return: %s' %
                                response.status)
            return response
        except Exception as e:
            if isinstance(e, httplib.BadStatusLine):
                msg = "Invalid server response"
            else:
                msg = unicode(e)
            lg.warn("[%d] Failed request '%s': %s (%0.2f seconds)"
                    % (self._rid(), self._request_str(conn, url), msg,
                       time.time() - issued_time))
            self._request_error = e
            is_conn_error = True
            return e
        finally:
            # Make sure we release the original connection provided by the
            # acquire_connection() call above.
            if self._client_conn is None:
                self._api_client.release_connection(conn, is_conn_error,
                                                    is_conn_service_unavail,
                                                    rid=self._rid())

    def _redirect_params(self, conn, headers, allow_release_conn=False):
        """Process redirect response, create new connection if necessary.

        Args:
            conn: connection that returned the redirect response
            headers: response headers of the redirect response
            allow_release_conn: if redirecting to a different server,
                release existing connection back to connection pool.

        Returns: Return tuple(conn, url) where conn is a connection object
            to the redirect target and url is the path of the API request
        """

        url = None
        for name, value in headers:
            if name.lower() == "location":
                url = value
                break
        if not url:
            lg.warn("[%d] Received redirect status without location header"
                    " field" % self._rid())
            return (conn, None)
        # Accept location with the following format:
        # 1. /path, redirect to same node
        # 2. scheme://hostname:[port]/path where scheme is https or http
        # Reject others
        # 3. e.g. relative paths, unsupported scheme, unspecified host
        result = urlparse.urlparse(url)
        if not result.scheme and not result.hostname and result.path:
            if result.path[0] == "/":
                if result.query:
                    url = "%s?%s" % (result.path, result.query)
                else:
                    url = result.path
                return (conn, url)      # case 1
            else:
                lg.warn("[%d] Received invalid redirect location: %s" %
                        (self._rid(), url))
                return (conn, None)     # case 3
        elif result.scheme not in ["http", "https"] or not result.hostname:
            lg.warn("[%d] Received malformed redirect location: %s" %
                    (self._rid(), url))
            return (conn, None)         # case 3
        # case 2, redirect location includes a scheme
        # so setup a new connection and authenticate
        if allow_release_conn:
            self._api_client.release_connection(conn)
        conn_params = (result.hostname, result.port, result.scheme == "https")
        conn = self._api_client.acquire_redirect_connection(conn_params, True,
                                                            self._headers)
        if result.query:
            url = "%s?%s" % (result.path, result.query)
        else:
            url = result.path
        return (conn, url)

    def _rid(self):
        '''Return current request id.'''
        return self._request_id

    @property
    def request_error(self):
        '''Return any errors associated with this instance.'''
        return self._request_error

    def _request_str(self, conn, url):
        '''Return string representation of connection.'''
        return "%s %s/%s" % (self._method, _conn_str(conn), url)
