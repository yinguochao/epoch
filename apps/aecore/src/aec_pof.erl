%%%=============================================================================
%%% @copyright 2018, Aeternity Anstalt
%%% @doc
%%%    Module defining the Proof of Fraud transaction
%%% @end
%%%=============================================================================

-module(aec_pof).

-include("blocks.hrl").

%% Behavior API
-export([deserialize_from_binary/1,
         new/1,
         serialization_template/1,
         serialize_to_binary/1
        ]).

%% Getters
-export([header/1,
         fraud_header/1]).

%% Validators
-export([check/1]).

-define(POF_VSN, 1).

-type pof() :: 'no_fraud' | map().
-export_type([pof/0]).

new({Header, FraudHeader}) ->
    #{header => Header, fraud_header => FraudHeader}.

-spec serialize_to_binary(map()) -> binary().
serialize_to_binary(#{header       := Header,
                      fraud_header := FraudHeader}) ->
    SerializedHdr      = aec_headers:serialize_to_binary(Header),
    SerializedFraudHdr = aec_headers:serialize_to_binary(FraudHeader),
    aec_object_serialization:serialize(
      pof,
      ?POF_VSN,
      serialization_template(?POF_VSN),
      [{header, SerializedHdr}, {fraud_header, SerializedFraudHdr}]).

-spec deserialize_from_binary(binary()) -> {'ok', map()} | {'error', term()}.
deserialize_from_binary(PoFBin) when is_binary(PoFBin) ->
    [ {header, SerializedHdr}
    , {fraud_header, SerializedFraudHdr}
    ] = aec_object_serialization:deserialize(
          pof,
          ?POF_VSN,
          serialization_template(?POF_VSN),
          PoFBin),
    #{header       => aec_headers:deserialize_from_binary(SerializedHdr),
      fraud_header => aec_headers:deserialize_from_binary(SerializedFraudHdr)}.

%%%===================================================================
%%% Getters
%%%===================================================================

-spec header(map()) -> aec_id:header().
header(#{header := Header}) ->
    Header.

-spec fraud_header(map()) -> aec_id:header().
fraud_header(#{fraud_header := FraudHeader}) ->
    FraudHeader.

%%%===================================================================
%%% Validation
%%%===================================================================

check(MicroHeader) ->
    PoF    = aec_headers:pof(MicroHeader),
    Prev   = aec_headers:prev_hash(MicroHeader),
    Height = aec_headers:height(MicroHeader),

    Parent = aec_chain:get_block(Prev),

    Checks =
        [fun() -> check_siblings(PoF) end,
         fun() -> check_if_first_microblock(Parent) end,
         fun() -> check_fraud_signatures(PoF, Height) end],

    case aeu_validation:run(Checks) of
        ok              -> ok;
        {error, Reason} -> {error, Reason}
    end.

check_siblings(#{header := Header1, fraud_header := Header2}) ->
    Height1 = aec_headers:height(Header1),
    Height2 = aec_headers:height(Header2),
    Prev1 = aec_headers:prev_hash(Header1),
    Prev2 = aec_headers:prev_hash(Header2),

    if (Height1 =:= Height2) and (Prev1 =:= Prev2) -> ok;
       true -> {error, not_siblings}
    end.

check_if_first_microblock(PrevBlock) ->
    case aec_blocks:type(PrevBlock) of
        key -> ok;
        micro -> {error, fraud_reported_in_not_first_micro}
    end.

check_fraud_signatures(#{header       := FraudHeader1,
                         fraud_header := FraudHeader2}, Height) ->

    MaliciousLeaderBlock = aec_chain:get_key_block_by_height(Height-1),
    MaliciousPubKey = aec_blocks:miner(MaliciousLeaderBlock),

    Sig1 = aeu_sig:verify(FraudHeader1, MaliciousPubKey),
    Sig2 = aeu_sig:verify(FraudHeader2, MaliciousPubKey),

    case {Sig1, Sig2} of
        {ok, ok} -> ok;
        _ -> {error, fraud_header_dont_match_leader_key}
    end.

%%%===================================================================
%%% Internals
%%%===================================================================

serialization_template(?POF_VSN) ->
    [ {header, binary}
    , {fraud_header, binary}].
