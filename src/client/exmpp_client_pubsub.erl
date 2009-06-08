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

%% @author Jean-Sébastien Pédron <js.pedron@meetic-corp.com>

-module(exmpp_client_pubsub).

-include("exmpp.hrl").

-export([
         get_subscriptions/1,
         get_subscriptions/2,
         get_affiliations/1,
         get_affiliations/2,
	 create_node/2,
	 create_node/3,
	 delete_node/2,
	 delete_node/3,
	 subscribe/3,
	 subscribe/4,
	 unsubscribe/3,
	 unsubscribe/4,
	 publish/3,
	 publish/4
	]).

%% --------------------------------------------------------------------
%% Publish/subscribe containers.
%% --------------------------------------------------------------------

%% @spec (Service) -> Pubsub_Iq
%%     Service = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for retrieving user subscriptions.
%%
%% The stanza `id' is generated automatically.

get_subscriptions(Service) ->
    get_subscriptions(pubsub_id(), Service).

%% @spec (Id, Service) -> Pubsub_Iq
%%     Id = string()
%%     Service = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for retrieving user subscriptions.

get_subscriptions(Id, Service) ->
    Subscriptions = #xmlel{ns = ?NS_PUBSUB, name = 'subscriptions'},
    Pubsub = exmpp_xml:append_child(
            #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
            Subscriptions),
    Iq = exmpp_xml:set_attributes(
            #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	    [{'type', "get"},
	     {'to', Service},
	     {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (Service) -> Pubsub_Iq
%%     Service = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for retrieving user affiliations.
%%
%% The stanza `id' is generated automatically.

get_subscriptions(Service) ->
    get_subscriptions(pubsub_id(), Service).

%% @spec (Id, Service) -> Pubsub_Iq
%%     Id = string()
%%     Service = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for retrieving user affiliations.

get_affiliations(Id, Service) ->
    Affiliations = #xmlel{ns = ?NS_PUBSUB, name = 'affiliations'},
    Pubsub = exmpp_xml:append_child(
            #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
	    Affiliations),
    Iq = exmpp_xml:set_attributes(
	    #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	    [{'type', "get"},
	     {'to', Service},
	     {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (Service, Node) -> Pubsub_Iq
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for creating a node on a pubsub service.
%%
%% The stanza `id' is generated automatically.

create_node(Service, Node) ->
    create_node(pubsub_id(), Service, Node).

%% @spec (Id, Service, Node) -> Pubsub_Iq
%%     Id = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for creating a node on a pubsub service.

create_node(Id, Service, Node) ->
    %% Make the <create/> element.
    Create = exmpp_xml:set_attributes(
	       #xmlel{ns = ?NS_PUBSUB, name = 'create'},
	       [{'node', Node}]),
    %% Prepare the final <iq/>.
    Pubsub = exmpp_xml:append_child(
	       #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
	       Create),
    Iq = exmpp_xml:set_attributes(
	   #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	   [{'type', "set"},
	    {'to', Service},
	    {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (Service, Node) -> Pubsub_Iq
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for deleting a node on a pubsub service.
%%
%% The stanza `id' is generated automatically.

delete_node(Service, Node) ->
    delete_node(pubsub_id(), Service, Node).

%% @spec (Id, Service, Node) -> Pubsub_Iq
%%     Id = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for deleting a node on a pubsub service.

delete_node(Id, Service, Node) ->
    %% Make the <delete/> element.
    Create = exmpp_xml:set_attributes(
	       #xmlel{ns = ?NS_PUBSUB_OWNER, name = 'delete'},
	       [{'node', Node}]),
    %% Prepare the final <iq/>.
    Pubsub = exmpp_xml:append_child(
	       #xmlel{ns = ?NS_PUBSUB_OWNER, name = 'pubsub'},
	       Create),
    Iq = exmpp_xml:set_attributes(
	   #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	   [{'type', "set"},
	    {'to', Service},
	    {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (From, Service, Node) -> Pubsub_Iq
%%     From = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for subscribing to a node on a pubsub service.
%%
%% The stanza `id' is generated automatically.

subscribe(From, Service, Node) ->
    subscribe(pubsub_id(), From, Service, Node).

%% @spec (Id, From, Service, Node) -> Pubsub_Iq
%%     Id = string()
%%     From = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for creating a node on a pubsub service.

subscribe(Id, From, Service, Node) ->
    %% Make the <subscribe/> element.
    Subscribe = exmpp_xml:set_attributes(
		  #xmlel{ns = ?NS_PUBSUB, name = 'subscribe'},
		  [{'node', Node},
		   {'jid', From}]),
    %% Prepare the final <iq/>.
    Pubsub = exmpp_xml:append_child(
	       #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
	       Subscribe),
    Iq = exmpp_xml:set_attributes(
	   #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	   [{'type', "set"},
	    {'to', Service},
	    {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (From, Service, Node) -> Pubsub_Iq
%%     From = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for unsubscribing from a node on a pubsub service.
%%
%% The stanza `id' is generated automatically.

unsubscribe(From, Service, Node) ->
    unsubscribe(pubsub_id(), From, Service, Node).

%% @spec (Id, From, Service, Node) -> Pubsub_Iq
%%     Id = string()
%%     From = string()
%%     Service = string()
%%     Node = string()
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for unsubscribing from a node on a pubsub service.

unsubscribe(Id, From, Service, Node) ->
    %% Make the <subscribe/> element.
    Unsubscribe = exmpp_xml:set_attributes(
		  #xmlel{ns = ?NS_PUBSUB, name = 'unsubscribe'},
		  [{'node', Node},
		   {'jid', From}]),
    %% Prepare the final <iq/>.
    Pubsub = exmpp_xml:append_child(
	       #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
	       Unsubscribe),
    Iq = exmpp_xml:set_attributes(
	   #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	   [{'type', "set"},
	    {'to', Service},
	    {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec (Service, Node, Items) -> Pubsub_Iq
%%     Service = string()
%%     Node = string()
%%     Items = [exmpp_xml:xmlel() | exmpp_xml:xmlcdata()]
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for publishing an item to a node on a pubsub service.
%%
%% The stanza `id' is generated automatically.

publish(Service, Node, Item_Child) when is_tuple(Item_Child) ->
    publish(pubsub_id(), Service, Node, [Item_Child]);

publish(Service, Node, Item_Children) ->
    publish(pubsub_id(), Service, Node, Item_Children).

%% @spec (Id, Service, Node, Items) -> Pubsub_Iq
%%     Id = string()
%%     From = string()
%%     Service = string()
%%     Node = string()
%%     Items = [exmpp_xml:xmlel() | exmpp_xml:xmlcdata()]
%%     Pubsub_Iq = exmpp_xml:xmlel()
%% @doc Make an `<iq>' for creating a node on a pubsub service.

publish(Id, Service, Node, Item_Child) when is_tuple(Item_Child) ->
    publish(Id, Service, Node, [Item_Child]);

publish(Id, Service, Node, Item_Children) ->
    %% Prepare item.
    Item = #xmlel{ns = ?NS_PUBSUB, name = 'item',
		  children = Item_Children},
    %% Make the <publish/> element.
    Publish = exmpp_xml:set_attributes(
		#xmlel{ns = ?NS_PUBSUB, name = 'publish',
		       children = [Item]},
		[{'node', Node}]),
    %% Prepare the final <iq/>.
    Pubsub = exmpp_xml:append_child(
	       #xmlel{ns = ?NS_PUBSUB, name = 'pubsub'},
	       Publish),
    Iq = exmpp_xml:set_attributes(
	   #xmlel{ns = ?NS_JABBER_CLIENT, name = 'iq'},
	   [{'type', "set"},
	    {'to', Service},
	    {'id', Id}]),
    exmpp_xml:append_child(Iq, Pubsub).

%% @spec () -> Pubsub_ID
%%     Pubsub_ID = string()
%% @doc Generate a random pubsub iq ID.
%%
%% This function uses {@link random:uniform/1}. It's up to the caller to
%% seed the generator.

pubsub_id() ->
    "pubsub-" ++ integer_to_list(random:uniform(65536 * 65536)).

