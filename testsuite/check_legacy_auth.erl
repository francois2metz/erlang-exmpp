% $Id$

-module(check_legacy_auth).
-vsn('$Revision$').

-include("exmpp.hrl").

-export([check/0, do_check/0]).

check() ->
    do_check(),
    testsuite:pass().

do_check() ->
    test_legacy_auth_request(),
    test_legacy_auth_fields(),
    test_legacy_auth_get_fields(),
    test_legacy_auth_password(),
    test_legacy_auth_success(),
    test_legacy_auth_failure(),
    ok.

% --------------------------------------------------------------------
% Legacy authentication testsuite.
% --------------------------------------------------------------------

-define(REQUEST1,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "get"},
      {xmlattr, undefined, undefined, 'id', "foobar"},
      {xmlattr, undefined, undefined, 'to', "dest"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query',
        [], []}
    ]}
).

-define(FIELDS1,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "result"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query',
        [], [
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'username', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'password', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'resource', [], []}
        ]}
    ]}
).

-define(FIELDS2,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "result"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query',
        [], [
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'username', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'digest', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'resource', [], []}
        ]}
    ]}
).

-define(FIELDS3,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "result"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query',
        [], [
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'username', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'password', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'digest', [], []},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'resource', [], []}
        ]}
    ]}
).

-define(PASSWORD1,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "set"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query',
        [], [
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'username', [], [{xmlcdata, <<"User">>}]},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'password', [], [{xmlcdata, <<"Password">>}]},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'resource', [], [{xmlcdata, <<"Resource">>}]}
        ]}
    ]}
).

-define(PASSWORD2,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "set"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], [
      {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined, 'query', [], [
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'username', [], [{xmlcdata, <<"User">>}]},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'digest', [],
            [{xmlcdata, <<"ab8bb63d7fb73e5b06b325ec1c147945cfac5a77">>}]},
          {xmlnselement, ?NS_JABBER_AUTH, undefined, undefined,
            'resource', [], [{xmlcdata, <<"Resource">>}]}
        ]}
    ]}
).

-define(SUCCESS1,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'type', "result"},
      {xmlattr, undefined, undefined, 'id', "foobar"}
    ], []}
).

-define(FAILURE1,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'id', "foobar"},
      {xmlattr, undefined, undefined, 'type', "error"}
    ], [
      {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'error',
        [
          {xmlattr, undefined, undefined, 'type', "auth"},
          {xmlattr, undefined, undefined, 'code', "401"}
        ], [
          {xmlnselement, ?NS_XMPP_STANZAS, undefined, undefined,
            'not-authorized', [], []}
        ]}
    ]}
).

-define(FAILURE2,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'id', "foobar"},
      {xmlattr, undefined, undefined, 'type', "error"}
    ], [
      {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'error',
        [
          {xmlattr, undefined, undefined, 'type', "cancel"},
          {xmlattr, undefined, undefined, 'code', "409"}
        ], [
          {xmlnselement, ?NS_XMPP_STANZAS, undefined, undefined,
            'conflict', [], []}
        ]}
    ]}
).

-define(FAILURE3,
  {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'iq', [
      {xmlattr, undefined, undefined, 'id', "foobar"},
      {xmlattr, undefined, undefined, 'type', "error"}
    ], [
      {xmlnselement, ?NS_JABBER_CLIENT, undefined, undefined, 'error',
        [
          {xmlattr, undefined, undefined, 'type', "modify"},
          {xmlattr, undefined, undefined, 'code', "406"}
        ], [
          {xmlnselement, ?NS_XMPP_STANZAS, undefined, undefined,
            'not-acceptable', [], []}
        ]}
    ]}
).

test_legacy_auth_request() ->
    testsuite:is(exmpp_client_legacy_auth:request("dest", "foobar"),
      ?REQUEST1),
    ok.

test_legacy_auth_fields() ->
    testsuite:is(exmpp_server_legacy_auth:fields(?REQUEST1, plain),
      ?FIELDS1),
    testsuite:is(exmpp_server_legacy_auth:fields(?REQUEST1, digest),
      ?FIELDS2),
    testsuite:is(exmpp_server_legacy_auth:fields(?REQUEST1, both),
      ?FIELDS3),
    testsuite:is(exmpp_server_legacy_auth:fields(?REQUEST1),
      ?FIELDS3),
    ok.

test_legacy_auth_get_fields() ->
    testsuite:is(exmpp_client_legacy_auth:get_fields(?FIELDS1),
      [username, password, resource]),
    testsuite:is(exmpp_client_legacy_auth:get_fields(?FIELDS2),
      [username, digest, resource]),
    testsuite:is(exmpp_client_legacy_auth:get_fields(?FIELDS3),
      [username, password, digest, resource]),
    ok.

test_legacy_auth_password() ->
    testsuite:is(exmpp_client_legacy_auth:password_plain(
        "User", "Password", "Resource", "foobar"),
      ?PASSWORD1),
    testsuite:is(exmpp_client_legacy_auth:password_digest(
        "User", "Password", "Resource", "foobar"),
      ?PASSWORD2),
    testsuite:is(exmpp_client_legacy_auth:password(
        ?FIELDS1, "User", "Password", "Resource", "foobar"),
      ?PASSWORD1),
    testsuite:is(exmpp_client_legacy_auth:password(
        ?FIELDS2, "User", "Password", "Resource", "foobar"),
      ?PASSWORD2),
    testsuite:is(exmpp_client_legacy_auth:password(
        ?FIELDS3, "User", "Password", "Resource", "foobar"),
      ?PASSWORD2),
    testsuite:is(exmpp_server_legacy_auth:get_credentials(?PASSWORD1),
      {"User", {plain, "Password"}, "Resource"}),
    Digest = exmpp_client_legacy_auth:digest("foobar", "Password"),
    testsuite:is(exmpp_server_legacy_auth:get_credentials(?PASSWORD2),
      {"User", {digest, Digest}, "Resource"}),
    ok.

test_legacy_auth_success() ->
    testsuite:is(exmpp_server_legacy_auth:success(?PASSWORD1),
      ?SUCCESS1),
    testsuite:is(exmpp_server_legacy_auth:success(?PASSWORD2),
      ?SUCCESS1),
    testsuite:is(exmpp_client_legacy_auth:is_success(?SUCCESS1),
      true),
    ok.

test_legacy_auth_failure() ->
    testsuite:is(exmpp_server_legacy_auth:failure(?PASSWORD1, 'not-authorized'),
      ?FAILURE1),
    testsuite:is(exmpp_server_legacy_auth:failure(?PASSWORD1, 'conflict'),
      ?FAILURE2),
    testsuite:is(exmpp_server_legacy_auth:failure(?PASSWORD1, 'not-acceptable'),
      ?FAILURE3),
    testsuite:is(exmpp_client_legacy_auth:is_success(?FAILURE1),
      false),
    ok.
