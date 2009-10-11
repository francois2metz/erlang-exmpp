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

%% The module <strong>{@module}</strong> implements the initiating
%% entity side of SASL authentication.
%%
%% <p>
%% Note that it doesn't implement SASL, only feature negotiation at the
%% XMPP level.
%% </p>

-module(exmpp_client_sasl).

-include("exmpp.hrl").

%% Feature announcement.
-export([
	 announced_mechanisms/1
	]).

%% SASL exchange.
-export([
	 selected_mechanism/1,
	 selected_mechanism/2,
	 decode_challenge/1,
	 sasl_step2/4,
	 sasl_step3/4,
	 response/1,
	 abort/0,
	 next_step/1
	]).

%% --------------------------------------------------------------------
%% Feature announcement.
%% --------------------------------------------------------------------

%% @spec (Features_Annoucenement) -> Mechanisms
%%     Features_Announcement = exmpp_xml:xmlel()
%%     Mechanisms = [string()]
%% @throws {sasl, announced_mechanisms, invalid_feature, Feature} |
%%         {sasl, announced_mechanisms, invalid_mechanism, El}
%% @doc Return the list of SASL mechanisms announced by the receiving entity.

announced_mechanisms(#xmlel{ns = ?NS_XMPP, name = 'features'} = El) ->
    case exmpp_xml:get_element(El, ?NS_SASL, 'mechanisms') of
        undefined  -> [];
        Mechanisms -> announced_mechanisms2(Mechanisms)
    end.

announced_mechanisms2(#xmlel{children = []} = Feature) ->
    throw({sasl, announced_mechanisms, invalid_feature, Feature});
announced_mechanisms2(#xmlel{children = Children}) ->
    announced_mechanisms3(Children, []).


announced_mechanisms3(
  [#xmlel{ns = ?NS_SASL, name = 'mechanism'} = El | Rest], Result) ->
    case exmpp_xml:get_cdata_as_list(El) of
        "" ->
            throw({sasl, announced_mechanisms, invalid_mechanism, El});
        Mechanism ->
            announced_mechanisms3(Rest, [Mechanism | Result])
    end;
announced_mechanisms3([El | _Rest], _Result) ->
    throw({sasl, announced_mechanisms, invalid_mechanism, El});
announced_mechanisms3([], Result) ->
    lists:reverse(Result).

%% --------------------------------------------------------------------
%% SASL exchange.
%% --------------------------------------------------------------------

%% @spec (Mechanism) -> Auth
%%     Mechanism = string()
%%     Auth = exmpp_xml:xmlel()
%% @doc Prepare an `<auth/>' element with the selected mechanism.

selected_mechanism(Mechanism) ->
    El = #xmlel{
      ns = ?NS_SASL,
      name = 'auth'
     },
    exmpp_xml:set_attribute(El, 'mechanism', Mechanism).

%% @spec (Mechanism, Initial_Response) -> Auth
%%     Mechanism = string()
%%     Initial_Response = string()
%%     Auth = exmpp_xml:xmlel()
%% @doc Prepare an `<auth/>' element with the selected mechanism.
%%
%% The initial response will be Base64-encoded before inclusion.

selected_mechanism(Mechanism, "") ->
    El = selected_mechanism(Mechanism),
    exmpp_xml:set_cdata(El, "=");
selected_mechanism(Mechanism, Initial_Response) ->
    El = selected_mechanism(Mechanism),
    exmpp_xml:set_cdata(El, base64:encode_to_string(Initial_Response)).

%% @spec (Response_Data) -> Response
%%     Response_Data = string()
%%     Response = exmpp_xml:xmlel()
%% @doc Prepare a `<response/>' element to send the challenge's response.
%%
%% `Response_Data' will be Base64-encoded.

response(Response_Data) ->
    El = #xmlel{
      ns = ?NS_SASL,
      name = 'response'
     },
    exmpp_xml:set_cdata(El, base64:encode_to_string(Response_Data)).

%% @spec () -> Abort
%%     Abort = exmpp_xml:xmlel()
%% @doc Make a `<abort/>' element.

abort() ->
    #xmlel{
       ns = ?NS_SASL,
       name = 'abort'
      }.

%% @spec (El) -> Type
%%     El = exmpp_xml:xmlel()
%%     Type = Challenge | Success | Failure
%%     Challenge = {challenge, string()}
%%     Success = {success, string()}
%%     Failure = {failure, Condition | undefined}
%%     Condition = atom()
%% @doc Extract the challenge or the ending element that the receiving
%% entity sent.
%%
%% Any challenge or success data is Base64-decoded.

next_step(#xmlel{ns = ?NS_SASL, name = 'challenge'} = El) ->
    Encoded = exmpp_xml:get_cdata_as_list(El),
    {challenge, base64:decode_to_string(Encoded)};
next_step(#xmlel{ns = ?NS_SASL, name = 'failure',
		 children = [#xmlel{ns = ?NS_SASL, name = Condition}]}) ->
    {failure, Condition};
next_step(#xmlel{ns = ?NS_SASL, name = 'failure'}) ->
    {failure, undefined};
next_step(#xmlel{ns = ?NS_SASL, name = 'success'} = El) ->
    Encoded = exmpp_xml:get_cdata_as_list(El),
    {success, base64:decode_to_string(Encoded)}.

decode_challenge(Data) ->
    [{"nonce", Nonce}, {"qop", Qop}, {"charset", Charset},{"algorithm", Algorithm}] = parse(Data),
    {Nonce, Qop, Charset, Algorithm}.
    
%% TODO: save Nonce and Cnonce
sasl_step2(ChallengeData, Username, Domain, Password) ->
    {Nonce, Qop, _Charset, _Algorithm} = decode_challenge(ChallengeData),
    Cnonce = integer_to_list(random:uniform(65536 * 65536)),
    Digest = "xmpp/"++ Domain,
    crypto:start(),
    Response_Data = encode(Username, Password, Domain, Nonce, Cnonce, Digest, "00000001", Qop),
    response(Response_Data).

%% TODO: use Nc and Qop
encode(Username, Password, Realm, Nonce, Cnonce, Digest, _Nc, _Qop) ->
    A1 = binary_to_list(crypto:md5(Username ++":" ++ Realm ++ ":" ++ Password)) ++ ":" ++ Nonce ++ ":" ++ Cnonce,
    A2 = "AUTHENTICATE:" ++ Digest,
    Response = hex(binary_to_list(crypto:md5(A1))) 
                   ++ ":" ++ Nonce ++ ":00000001:" 
                   ++ Cnonce ++ ":auth:" ++ hex(binary_to_list(crypto:md5(A2))),
    Response2 = hex(binary_to_list(crypto:md5(Response))),
    "username=\"" ++ Username ++ "\"," ++
        "realm=\""    ++ Realm    ++ "\"," ++
        "nonce=\""    ++ Nonce    ++ "\"," ++
        "cnonce=\""   ++ Cnonce   ++ "\"," ++
        "nc=\"00000001\"," ++
        "qop=\"auth\"," ++
        "digest-uri=\"" ++ Digest ++ "\"," ++
        "response=\"" ++ Response2 ++ "\"," ++
        "charset=\"utf-8\"".

%% TODO: Check Challenge data
sasl_step3(_ChallengeData, _Username, _Domain, _Password) ->
    #xmlel{
            ns = ?NS_SASL,
            name = 'response'
           }.
    %% A1 = binary_to_list(crypto:md5(Username ++":"++ Domain ++":"++ Password)) ++
    %%     ":"++ Nonce ++":"++ Cnonce,
    %% A2 = ":"+ Digest,

    %% Rspauth = hex(binary_to_list(crypto:md5(A1))) ++ ":"++ Nonce ++":"++ Nc ++":" ++
    %%                     Cnonce ++ ":auth:"++ hex(binary_to_list(crypto:md5(A2))),
    %% case hex(binary_to_list(crypto:md5(RspAuth))) of
    %%     ChallengeData ->
    %%         #xmlel{
    %%             ns = ?NS_SASL,
    %%             name = 'response'
    %%         };
    %%     _ ->
    %%         abort()
    %% end.

%% From ejabberd (cyrsasl_digest.erl)    
hex(S) ->
    hex(S, []).

hex([], Res) ->
    lists:reverse(Res);
hex([N | Ns], Res) ->
    hex(Ns, [digit_to_xchar(N rem 16),
             digit_to_xchar(N div 16) | Res]).


digit_to_xchar(D) when (D >= 0) and (D < 10) ->
    D + 48;
digit_to_xchar(D) ->
    D + 87.


parse(S) ->
    parse1(S, "", []).

parse1([$= | Cs], S, Ts) ->
    parse2(Cs, lists:reverse(S), "", Ts);
parse1([$, | Cs], [], Ts) ->
    parse1(Cs, [], Ts);
parse1([$\s | Cs], [], Ts) ->
    parse1(Cs, [], Ts);
parse1([C | Cs], S, Ts) ->
    parse1(Cs, [C | S], Ts);
parse1([], [], T) ->
    lists:reverse(T);
parse1([], _S, _T) ->
    bad.

parse2([$\" | Cs], Key, Val, Ts) ->
    parse3(Cs, Key, Val, Ts);
parse2([C | Cs], Key, Val, Ts) ->
    parse4(Cs, Key, [C | Val], Ts);
parse2([], _, _, _) ->
    bad.

parse3([$\" | Cs], Key, Val, Ts) ->
    parse4(Cs, Key, Val, Ts);
parse3([$\\, C | Cs], Key, Val, Ts) ->
    parse3(Cs, Key, [C | Val], Ts);
parse3([C | Cs], Key, Val, Ts) ->
    parse3(Cs, Key, [C | Val], Ts);
parse3([], _, _, _) ->
    bad.

parse4([$, | Cs], Key, Val, Ts) ->
    parse1(Cs, "", [{Key, lists:reverse(Val)} | Ts]);
parse4([$\s | Cs], Key, Val, Ts) ->
    parse4(Cs, Key, Val, Ts);
parse4([C | Cs], Key, Val, Ts) ->
    parse4(Cs, Key, [C | Val], Ts);
parse4([], Key, Val, Ts) ->
    parse1([], "", [{Key, lists:reverse(Val)} | Ts]).
