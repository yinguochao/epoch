%%%=============================================================================
%%% @copyright 2018, Aeternity Anstalt
%%% @doc
%%%    Module defining the Proof of Fraud transaction
%%% @end
%%%=============================================================================

-module(aec_pof_tx).

-behavior(aetx).

%% Behavior API
-export([new/1,
         type/0,
         fee/1,
         ttl/1,
         nonce/1,
         origin/1,
         check/5,
         process/6,
         signers/2,
         serialization_template/1,
         serialize/1,
         deserialize/2,
         for_client/1
        ]).

%% Getters
-export([header/1,
         fraud_header/1,
         offender/1,
         reporter/1]).

%%%===================================================================
%%% Types
%%%===================================================================

-define(POF_TX_VSN, 1).
-define(POF_TX_TYPE, pof_tx).

-record(pof_tx, {
          reporter     :: aec_id:id(),
          offender     :: aec_id:id(),
          header       :: aec_id:headers(),
          fraud_header :: aec_id:headers(),
          fee   = 0    :: non_neg_integer(),
          ttl   = 0    :: aetx:tx_ttl(),
          nonce = 0    :: non_neg_integer()}).

-opaque tx() :: #pof_tx{}.

-export_type([tx/0]).

%%%===================================================================
%%% Behaviour API
%%%===================================================================

-spec new(map()) -> {ok, aetx:tx()}.
new(#{reporter     := Reporter,
      offender     := Offender,
      header       := Header,
      fraud_header := FraudHeader,
      fee          := Fee,
      nonce        := Nonce} = Args) when is_integer(Nonce), Nonce >= 0,
                                          is_integer(Fee), Fee >= 0,
                                          is_binary(Header),
                                          is_binary(FraudHeader) ->
    assert_reporter(Reporter),
    assert_offender(Offender),
    Tx = #pof_tx{reporter     = Reporter,
                 offender     = Offender,
                 header       = Header,
                 fraud_header = FraudHeader,
                 fee          = Fee,
                 ttl          = maps:get(ttl, Args, 0),
                 nonce        = Nonce},
    {ok, aetx:new(?MODULE, Tx)}.

assert_reporter(Id) ->
    case aec_id:specialize_type(Id) of
        account -> ok;
        Other   -> error({illegal_id_type, Other})
    end.

assert_offender(Id) ->
    case aec_id:specialize_type(Id) of
        account -> ok;
        Other   -> error({illegal_id_type, Other})
    end.

-spec type() -> atom().
type() ->
    ?POF_TX_TYPE.

-spec fee(tx()) -> integer().
fee(#pof_tx{fee = F}) ->
    F.

-spec ttl(tx()) -> aetx:tx_ttl().
ttl(#pof_tx{ttl = TTL}) ->
    TTL.

-spec nonce(tx()) -> non_neg_integer().
nonce(#pof_tx{nonce = Nonce}) ->
    Nonce.

-spec origin(tx()) -> aec_keys:pubkey().
origin(#pof_tx{} = Tx) ->
    reporter_pubkey(Tx).

-spec check(tx(), aetx:tx_context(), aec_trees:trees(), aec_blocks:height(), non_neg_integer()) ->
                   {ok, aec_trees:trees()} | {error, term()}.
check(#pof_tx{} = PoFTx, _Context, Trees, _Height, _ConsensusVersion) ->
    Checks = [fun check_reporter_account/2],
    %% TODO: write check to compare offending and local header
    case aeu_validation:run(Checks, [PoFTx, Trees]) of
        ok ->
            case resolve_reporter(PoFTx, Trees) of
                {ok, RecipientPubkey} ->
                    {ok, aec_trees:ensure_account(RecipientPubkey, Trees)};
                {error, _} = E ->
                    E
            end;
        {error, _Reason} = Error ->
            Error
    end.

-spec process(tx(), aetx:tx_context(), aec_trees:trees(), aec_blocks:height(),
              non_neg_integer(), binary() | no_tx_hash) -> {ok, aec_trees:trees()}.
process(PoFTx, _Context, Trees0, _Height, _ConsensusVersion, _TxHash) ->

    {ok, RecipientPubkey} = resolve_reporter(PoFTx, Trees0),
    AccountsTrees0 = aec_trees:accounts(Trees0),

    %% TODO: remove funds from malicious leader
    %%       or just never apply coinbase - if it is in delayed

    {value, RecipientAccount0} = aec_accounts_trees:lookup(RecipientPubkey, AccountsTrees0),
    {ok, RecipientAccount} = aec_accounts:earn(RecipientAccount0, aec_governance:fraud_reward()),
    AccountsTrees1 = aec_accounts_trees:enter(RecipientAccount, AccountsTrees0),

    Trees = aec_trees:set_accounts(Trees0, AccountsTrees1),
    {ok, Trees}.

-spec signers(tx(), aec_trees:trees()) -> {ok, [aec_keys:pubkey()]}.
signers(#pof_tx{} = Tx, _) -> {ok, [reporter_pubkey(Tx)]}.
serialize(#pof_tx{
             reporter = Reporter,
             offender = Offender,
             header = Header,
             fraud_header = FraudHeader,
             fee = Fee,
             ttl = TTL,
             nonce = Nonce}) ->
    {version(),
     [ {reporter, Reporter}
     , {header, Header}
     , {fraud_header, FraudHeader}
     , {offender, Offender}
     , {fee, Fee}
     , {ttl, TTL}
     , {nonce, Nonce}
     ]}.

deserialize(?POF_TX_VSN,
            [ {reporter, Reporter}
            , {header, Header}
            , {fraud_header, FraudHeader}
            , {offender, Offender}
            , {fee, Fee}
            , {ttl, TTL}
            , {nonce, Nonce}
            ]) ->
    %% Asserts
    account = aec_id:specialize_type(Reporter),
    #pof_tx{
       reporter = Reporter,
       header = Header,
       fraud_header = FraudHeader,
       offender = Offender,
       fee = Fee,
       ttl = TTL,
       nonce = Nonce}.

serialization_template(?POF_TX_VSN) ->
    [ {reporter, id}
    , {offender, id}
    , {header, binary}               %% TODO: add header tag?
    , {fraud_header, binary}  %% TODO: add header tag?
    , {fee, int}
    , {ttl, int}
    , {nonce, int}
    ].

for_client(#pof_tx{
              header = Header,
              fraud_header = FraudHeader,
              fee = Fee,
              ttl = TTL,
              nonce = Nonce} = Tx) ->
    #{<<"reporter">> => aec_base58c:encode(id_hash, reporter(Tx)),
      <<"data_schema">> => <<"SpendTxJSON">>, % swagger schema name
      <<"offender">> => aec_base58c:encode(id_hash, offender(Tx)),
      <<"header">> => Header,
      <<"fraud_header">> => FraudHeader,
      <<"fee">> => Fee,
      <<"ttl">> => TTL,
      <<"nonce">> => Nonce,
      <<"vsn">> => version()}.

%%%===================================================================
%%% Getters
%%%===================================================================

-spec header(tx()) -> aec_id:header().
header(#pof_tx{header = Header}) ->
    Header.

-spec fraud_header(tx()) -> aec_id:header().
fraud_header(#pof_tx{fraud_header = FraudHeader}) ->
    FraudHeader.

-spec offender(tx()) -> aec_id:id().
offender(#pof_tx{offender = Offender}) ->
    Offender.

-spec reporter(tx()) -> aec_id:id().
reporter(#pof_tx{reporter = Reporter}) ->
    Reporter.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec reporter_pubkey(tx()) -> aec_keys:pubkey().
reporter_pubkey(#pof_tx{reporter = Reporter}) ->
    aec_id:specialize(Reporter, account).

-spec check_reporter_account(tx(), aec_trees:trees())  ->
                                    ok | {error, term()}.
check_reporter_account(#pof_tx{fee = Fee, nonce = TxNonce} = Tx,
                       Trees) ->
    ReporterPubkey = reporter_pubkey(Tx),
    aetx_utils:check_account(ReporterPubkey, Trees, TxNonce, Fee).

resolve_reporter(#pof_tx{reporter = Reporter}, _Trees) ->
    {account,  RecipientPubkey} = aec_id:specialize(Reporter),
    {ok, RecipientPubkey}.

version() ->
    ?POF_TX_VSN.
