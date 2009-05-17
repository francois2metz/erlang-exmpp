% $Id: exmpp_bosh.erl 603 2008-08-20 12:22:03Z mremond $

%% @author Mickael Remond <mickael.remond@process-one.net>

%% @doc
%% The module <strong>{@module}</strong> manages XMPP over HTTP connection
%% according to the BOSH protocol (XEP-0124: Bidirectional-streams Over
%% Synchronous HTTP)
%%
%% <p>
%% This module is not intended to be used directly by client developers.
%% </p>
%%
%% <p>This code is copyright Process-one (http://www.process-one.net/)</p>
%%

-module(exmpp_bosh).

-include_lib("exmpp/include/exmpp.hrl").

%% Behaviour exmpp_gen_transport ?
-export([connect/3, send/2, close/2]).

%% Internal export
-export([bosh_session/1,
	 bosh_send_async/5,
	 bosh_recv_async/4]).

-define(CONTENT_TYPE, "text/xml; charset=utf-8").
-define(HOLD, "2").
-define(VERSION, "1.7").
-define(WAIT, "3600").

-record(state, {bosh_url="",
		domain="",
		sid = <<>>,
		rid = 0,
		auth_id = <<>>,
		client_pid,
		stream_ref,
		pending_requests=[] %% For now, we put only one receiver
	       }).

%% TODO: We do not support yet BOSH route attribute.

%% Connect to XMPP server
%% Returns: Ref
connect(ClientPid, StreamRef, {URL, Domain, _Port}) ->
    State = session_creation(URL, Domain),
    BoshManagerPid = spawn_link(?MODULE, bosh_session,
				[State#state{bosh_url=URL,
					     domain=Domain,
					     client_pid=ClientPid,
					     stream_ref=StreamRef}]),
    activate(BoshManagerPid),
    {BoshManagerPid, undefined}.

activate(BoshManagerPid) ->
    Ref=make_ref(),
    BoshManagerPid ! {activate,self(),Ref},
    receive
	{Ref, ok} ->
	    ok
    after 5000 ->
	    BoshManagerPid ! stop,
	    erlang:throw({socket_error, cannot_activate_socket})
    end.

close(BoshManagerPid, undefined) ->
    BoshManagerPid ! stop.

send(BoshManagerPid, XMLPacket) ->
    BoshManagerPid ! {send, XMLPacket},
    ok.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
bosh_session(State) ->
    %% Set name of wrapping level 1 tag for BOSH (body)
    XMLStream = exmpp_xmlstream:set_wrapper_tagnames(State#state.stream_ref,
						     [body]),

    %% Handle repeting HTTP recv request
    process_flag(trap_exit, true),
    NewRID = State#state.rid + 1,
    RecvPid = bosh_recv(State#state.bosh_url, State#state.sid, NewRID),

    bosh_session_loop(State#state{rid=NewRID, stream_ref=XMLStream,
				  pending_requests=[RecvPid]}).

bosh_session_loop(State) ->
    [RecvPid] = State#state.pending_requests,
    receive
	{activate, Pid, Ref} ->
	    Pid ! {Ref, ok},
	    bosh_session_loop(State);
	%% Ignore client sending opening stream. It is not needed.
	%% The session manager need a stream open reply from server however:
 	{send, #xmlel{ns=?NS_XMPP, name='stream'}} ->
	    AuthId = binary_to_list(State#state.auth_id),
	    Domain = State#state.domain,
	    StreamStart = "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='" ++ Domain ++ "' id='" ++ AuthId ++ "'>",
	    {ok, StreamRef}=exmpp_xmlstream:parse(State#state.stream_ref, StreamStart),
	    bosh_session_loop(State#state{stream_ref=StreamRef});
	{send, XMLPacket} ->
	    NewRid = State#state.rid + 1,
	    bosh_send(State#state.bosh_url,
		      State#state.sid,
		      NewRid, XMLPacket),
	    bosh_session_loop(State#state{rid=NewRid});
	{recv, XMLString} ->
	    {ok, NewStreamRef} = exmpp_xmlstream:parse(State#state.stream_ref,
						       XMLString),
	    bosh_session_loop(State#state{stream_ref=NewStreamRef});
	{'EXIT',RecvPid,normal} ->
	    NewRID = State#state.rid + 1,
	    NewRecvPid = bosh_recv(State#state.bosh_url, State#state.sid, NewRID),
	    bosh_session_loop(State#state{rid=NewRID,
					  pending_requests=[NewRecvPid]});
	stop ->
	    ok;
	Unknown	->
	    %% TODO: Use ProcessOne logging application
	    %% io:format("Unknown message received: ~p", [Unknown]),
	    bosh_session_loop(State)
    end.

bosh_send(URL, SID, NewRID, XMLPacket) ->
    spawn_link(?MODULE, bosh_send_async, [self(), URL, SID, NewRID, XMLPacket]).

bosh_send_async(BoshManagerPid, URL, SID, NewRID, XMLPacket) ->
    %% TODO: Make sure root element as xmlns = jabber:client
    %% Force xmlns to jabber:client, but be carefull of not duplicating
    %% attribute
    Body = exmpp_xml:set_attributes(
	     #xmlel{ns = ?NS_BOSH_s, name = 'body'},
	     [{sid, SID},
	      {rid, integer_to_list(NewRID)}]),
    PostBody = exmpp_xml:set_children(Body, [XMLPacket]),
    BinaryPacket = exmpp_xml:document_to_binary(PostBody),
    Reply = http:request(post, {URL, [], [], BinaryPacket}, [], []),
    %% io:format("send Reply =~p~n",[Reply]),
    process_http_reply(BoshManagerPid, Reply).

bosh_recv(URL, SID, NewRID) ->
    spawn_link(?MODULE, bosh_recv_async, [self(), URL, SID, NewRID]).

bosh_recv_async(BoshManagerPid, URL, SID, NewRID) ->
    PostBody = exmpp_xml:set_attributes(
		 #xmlel{ns = ?NS_BOSH_s, name = 'body'},
		 [{sid, SID}, {rid, integer_to_list(NewRID)}]),
    Reply = http:request(
	      post, {URL, [], [],
		     exmpp_xml:document_to_binary(PostBody)}, [], []),
    %% io:format("MREMOND recv: ~p~n",[Reply]),
    process_http_reply(BoshManagerPid, Reply).

process_http_reply(BoshManagerPid, {ok, {{"HTTP/1.1", 200, "OK"},
				    _Headers, Body}}) ->
    BoshManagerPid ! {recv, Body};
%% TODO: Handle errors.
process_http_reply(BoshManagerPid, _HTTPReply) ->
    ok.

%% Session creation request
%% See XEP-0124 - Section 7.1
session_creation(URL, Domain) ->
    RID = random:uniform(65536 * 65536),
    PostBody = exmpp_xml:set_attributes(
		 #xmlel{ns = ?NS_BOSH_s, name = 'body'},
		 [{content, ?CONTENT_TYPE},
		  {hold, ?HOLD},
		  {to, Domain},
		  {ver, ?VERSION},
		  {wait, ?WAIT},
		  {rid, integer_to_list(RID)}]),
    %% TODO: extract port from URL ?
    case http:request(post, {URL, [], [], exmpp_xml:document_to_binary(PostBody)}, [], []) of
	{ok, {{"HTTP/1.1",200,"OK"}, _Headers, Body}} ->
	    %% Parse reply body
	    [#xmlel{name=body} = BodyEl] = exmpp_xml:parse_document(Body),
	    SID = exmpp_xml:get_attribute_as_binary(BodyEl, sid, undefined),
	    AuthID = exmpp_xml:get_attribute_as_binary(BodyEl, authid, undefined),
	    #state{sid=SID, rid=RID, auth_id=AuthID};
	%% TODO: Handle non-200 replies
	{error, Reason} ->
	    throw({'cannot-create-session', Reason})
    end.

%% Implementation notes. For now the design is pretty basic. The main
%% loop spawn process to handle HTTP queries. Currently it takes care
%% of a single HTTP receive request, that is respawned when it expire
%% / return result.
