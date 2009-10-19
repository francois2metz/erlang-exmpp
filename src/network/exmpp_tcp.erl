%% Copyright ProcessOne 2006-2009. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.

%% @author Mickael Remond <mickael.remond@process-one.net>

%% @doc
%% The module <strong>{@module}</strong> manages simple TCP/IP socket
%% connections to an XMPP server.
%%
%% <p>
%% This module is intended to be used directly by client developers.
%% </p>

-module(exmpp_tcp).

-include("exmpp.hrl").

%% Behaviour exmpp_gen_transport ?
-export([connect/3, send/2, close/2, starttls/3]).

%% Internal export
-export([receiver/3]).

%% Connect to XMPP server
%% Returns:
%% Ref or throw error
connect(ClientPid, StreamRef, {Host, Port}) ->
    case gen_tcp:connect(Host, Port, [{packet,0},
				      binary,
				      {active, false},
				      {reuseaddr, true}], 30000) of
	{ok, Socket} ->
	    %% TODO: Hide receiver failures in API
	    ReceiverPid = spawn_link(?MODULE, receiver,
				     [ClientPid, Socket, StreamRef]),
	    gen_tcp:controlling_process(Socket, ReceiverPid),
	    activate(ReceiverPid),
	    {Socket, ReceiverPid};
	{error, Reason} ->
	    erlang:throw({socket_error, Reason})
    end.

activate(ReceiverPid) ->
    Ref=make_ref(),
    ReceiverPid ! {activate,self(),Ref},
    receive
	{Ref, ok} ->
	    ok
    after 5000 ->
	    ReceiverPid ! stop,
	    erlang:throw({socket_error, cannot_activate_socket})
    end.

%% if we use active-once before spawning the receiver process,
%% we can receive some data in the original process rather than
%% in the receiver process. So {active,once} is is set explicitly
%% in the receiver process. NOTE: in this case this wouldn't make
%% a big difference, as the connecting client should send the
%% stream header before receiving anything

close(Socket, ReceiverPid) ->
    ReceiverPid ! stop,
    gen_tcp:close(Socket).

send({tls_socket, _, _, _} = Socket, XMLPacket) ->
    String = exmpp_xml:document_to_binary(XMLPacket),
    send_tls(Socket, String);

send(Socket, XMLPacket) when is_record(XMLPacket, xmlel) ->
    String = exmpp_xml:document_to_binary(XMLPacket),
    send(Socket, String);

send(Socket, String) ->
    case gen_tcp:send(Socket, String) of
	ok -> ok;
	{error, Reason} -> 
            {error, Reason}
    end.

send_tls(Socket, String) ->
    case exmpp_tls:send(Socket, String) of
	ok -> ok;
	{error, Reason} -> {error, Reason}
    end.

starttls(Socket, ReceiverPid, StreamRef) when is_port(Socket) ->
    Ret = {tls_socket, _, _, _} = exmpp_tls:connect({gen_tcp, Socket}, 
                                                    undefined, 
                                                    false, 
                                                    [{engine, openssl}, {mode, binary}]),
    ReceiverPid ! {tls, Ret, StreamRef},
    Ret.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
receiver(ClientPid, Socket, StreamRef) ->
    receiver_loop(ClientPid, Socket, StreamRef).

receiver_loop(ClientPid, Socket, StreamRef) ->
    receive
	{activate, Pid, Ref} ->
	    inet:setopts(Socket, [{active, once}]),
	    Pid ! {Ref, ok},
	    receiver_loop(ClientPid, Socket, StreamRef);
        {tls, SocketDesc, StreamRef2} ->
            receiver_loop_tls(ClientPid, SocketDesc, StreamRef2);
	stop ->
	    ok;
	{tcp, Socket, Data} ->
	    inet:setopts(Socket, [{active, once}]),
	    {ok, NewStreamRef} = exmpp_xmlstream:parse(StreamRef, Data),
	    receiver_loop(ClientPid, Socket, NewStreamRef);
	{tcp_closed, Socket} ->
	    %% XXX why timeouts with timeout 10 seconds with quickchek tests ???
	    gen_fsm:sync_send_all_state_event(ClientPid, tcp_closed, 20000)
    end.

receiver_loop_tls(ClientPid, SocketDesc, StreamRef) ->
    receive
	stop ->
	    ok;
	{tcp, Socket, Data} ->
	    inet:setopts(Socket, [{active, once}]),
            {ok, Data2} = exmpp_tls:recv_data(SocketDesc, Data),
            {ok, NewStreamRef} = exmpp_xmlstream:parse(StreamRef, Data2),
            receiver_loop_tls(ClientPid, SocketDesc, NewStreamRef);
	{tcp_closed, _Socket} ->
	    %% XXX why timeouts with timeout 10 seconds with quickchek tests ???
	    gen_fsm:sync_send_all_state_event(ClientPid, tcp_closed, 20000)
    end.
