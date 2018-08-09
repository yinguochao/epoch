-module(aehttp_dispatch_int).

-export([handle_request/3]).

-import(aeu_debug, [pp/1]).
-import(aehttp_helpers, [ parse_filter_param/2
                        , get_block/2
                        , get_block/3
                        , get_block_from_chain/1
                        , parse_map_to_atom_keys/0
                        , read_required_params/1
                        , read_optional_params/1
                        , base58_decode/1
                        , get_nonce_from_account_id/1
                        , verify_name/1
                        , nameservice_pointers_decode/1
                        , unsigned_tx_response/1
                        , process_request/2
                        ]).

-spec handle_request(
        OperationID :: atom(),
        Req :: map(),
        Context :: #{}
                   ) -> {Status :: cowboy:http_status(), Headers :: list(), Body :: map()}.

handle_request('PostSpend', #{'SpendTx' := Req}, _Context) ->
    AllowedRecipients = [account_pubkey, name, oracle_pubkey, contract_pubkey],
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([sender_id,
                                       {recipient_id, recipient_id},
                                        amount, fee, payload]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{sender_id, sender_id, {id_hash, [account_pubkey]}},
                                {recipient_id, recipient_id,
                                 {id_hash, AllowedRecipients}}]),
                 get_nonce_from_account_id(sender_id),
                 unsigned_tx_response(fun aec_spend_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostNamePreclaim', #{'NamePreclaimTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([account_id, commitment_id, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{account_id, account_id, {id_hash, [account_pubkey]}},
                                {commitment_id, commitment_id, {id_hash, [commitment]}}]),
                 get_nonce_from_account_id(account_id),
                 unsigned_tx_response(fun aens_preclaim_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostNameUpdate', #{'NameUpdateTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([account_id, name_id, name_ttl,
                                       pointers, client_ttl, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{account_id, account_id, {id_hash, [account_pubkey]}},
                                {name_id, name_id, {id_hash, [name]}}]),
                 nameservice_pointers_decode(pointers),
                 get_nonce_from_account_id(account_id),
                 unsigned_tx_response(fun aens_update_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostNameClaim', #{'NameClaimTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([account_id, name, name_salt, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{account_id, account_id, {id_hash, [account_pubkey]}},
                                {name, name, name}]),
                 get_nonce_from_account_id(account_id),
                 verify_name(name),
                 unsigned_tx_response(fun aens_claim_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostNameTransfer', #{'NameTransferTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([account_id, name_id, recipient_id, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{account_id, account_id, {id_hash, [account_pubkey]}},
                                {recipient_id, recipient_id,
                                 {id_hash, [account_pubkey, name]}},
                                {name_id, name_id, {id_hash, [name]}}]),
                 get_nonce_from_account_id(account_id),
                 unsigned_tx_response(fun aens_transfer_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostNameRevoke', #{'NameRevokeTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([account_id, name_id, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{account_id, account_id, {id_hash, [account_pubkey]}},
                                {name_id, name_id, {id_hash, [name]}}]),
                 get_nonce_from_account_id(account_id),
                 unsigned_tx_response(fun aens_revoke_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostChannelCreate', #{'ChannelCreateTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([initiator_id, initiator_amount,
                                       state_hash,
                                       responder_id, responder_amount,
                                       push_amount, channel_reserve,
                                       lock_period, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{initiator_id, initiator_id, {id_hash, [account_pubkey]}},
                                {responder_id, responder_id, {id_hash, [account_pubkey]}},
                                {state_hash, state_hash, state}
                               ]),
                 get_nonce_from_account_id(initiator_id),
                 unsigned_tx_response(fun aesc_create_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostChannelDeposit', #{'ChannelDepositTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([channel_id, from_id,
                                       amount, fee, state_hash, round, nonce]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{channel_id, channel_id, {id_hash, [channel]}},
                                {from_id, from_id, {id_hash, [account_pubkey]}},
                                {state_hash, state_hash, state}]),
                 unsigned_tx_response(fun aesc_deposit_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostChannelWithdraw', #{'ChannelWithdrawTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([channel_id, to_id,
                                       amount, fee, state_hash, round, nonce]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{channel_id, channel_id, {id_hash, [channel]}},
                                {to_id, to_id, {id_hash, [account_pubkey]}},
                                {state_hash, state_hash, state}]),
                 unsigned_tx_response(fun aesc_withdraw_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostChannelSnapshotSolo', #{'ChannelSnapshotSoloTx' := Req}, _Context) ->
    ParseFuns = [parse_map_to_atom_keys(),
                 read_required_params([channel_id, from_id,
                                       payload, fee]),
                 read_optional_params([{ttl, ttl, '$no_value'}]),
                 base58_decode([{channel_id, channel_id, {id_hash, [channel]}},
                                {from_id, from_id, {id_hash, [account_pubkey]}}]),
                 get_nonce_from_account_id(from_id),
                 unsigned_tx_response(fun aesc_snapshot_solo_tx:new/1)
                ],
    process_request(ParseFuns, Req);

handle_request('PostOracleRegisterTx', #{'OracleRegisterTx' := OracleRegisterTxObj}, _Context) ->
    #{<<"query_format">>    := QueryFormat,
      <<"response_format">> := ResponseFormat,
      <<"query_fee">>       := QueryFee,
      <<"oracle_ttl">>      := OracleTTL,
      <<"fee">>             := Fee} = OracleRegisterTxObj,
    TTL = maps:get(<<"ttl">>, OracleRegisterTxObj, 0),
    TTLType = binary_to_existing_atom(maps:get(<<"type">>, OracleTTL), utf8),
    TTLValue = maps:get(<<"value">>, OracleTTL),
    case aehttp_int_tx_logic:oracle_register(QueryFormat, ResponseFormat,
                                             QueryFee, Fee, TTLType, TTLValue, TTL) of
        {ok, Tx} ->
            {Pubkey, TxHash} = aehttp_int_tx_logic:sender_and_hash(Tx),
            {200, [], #{oracle_id => aec_base58c:encode(oracle_pubkey, Pubkey),
                        tx_hash => aec_base58c:encode(tx_hash, TxHash)}};
        {error, account_not_found} ->
            {404, [], #{reason => <<"Account not found">>}};
        {error, key_not_found} ->
            {404, [], #{reason => <<"Keys not configured">>}}
    end;

handle_request('PostOracleExtendTx', #{'OracleExtendTx' := OracleExtendTxObj}, _Context) ->
    #{<<"oracle_ttl">> := OracleTTL,
      <<"fee">>        := Fee} = OracleExtendTxObj,
    TTL = maps:get(<<"ttl">>, OracleExtendTxObj, 0),
    TTLType = delta,
    TTLValue = maps:get(<<"value">>, OracleTTL),
    case aehttp_int_tx_logic:oracle_extend(Fee, TTLType, TTLValue, TTL) of
        {ok, Tx} ->
            {Pubkey, TxHash} = aehttp_int_tx_logic:sender_and_hash(Tx),
            {200, [], #{oracle_id => aec_base58c:encode(oracle_pubkey, Pubkey),
                        tx_hash => aec_base58c:encode(tx_hash, TxHash)}};
        {error, account_not_found} ->
            {404, [], #{reason => <<"Account not found">>}};
        {error, key_not_found} ->
            {404, [], #{reason => <<"Keys not configured">>}}
    end;

handle_request('PostOracleQueryTx', #{'OracleQueryTx' := OracleQueryTxObj}, _Context) ->
    #{<<"oracle_pubkey">> := EncodedOraclePubkey,
      <<"query">>         := Query,
      <<"query_fee">>     := QueryFee,
      <<"query_ttl">>     := QueryTTL,
      <<"response_ttl">>  :=
          #{<<"type">>    := <<"delta">>,
            <<"value">>   := ResponseTTLValue},
      <<"fee">>           := Fee} = OracleQueryTxObj,
    TTL = maps:get(<<"ttl">>, OracleQueryTxObj, 0),
    QueryTTLType = binary_to_existing_atom(maps:get(<<"type">>, QueryTTL), utf8),
    QueryTTLValue= maps:get(<<"value">>, QueryTTL),
    case aehttp_int_tx_logic:oracle_query(EncodedOraclePubkey, Query, QueryFee, QueryTTLType,
             QueryTTLValue, ResponseTTLValue, Fee, TTL) of
        {ok, Tx, QId} ->
            {_, TxHash} = aehttp_int_tx_logic:sender_and_hash(Tx),
            {200, [], #{query_id => aec_base58c:encode(oracle_query_id, QId),
                        tx_hash => aec_base58c:encode(tx_hash, TxHash)}};
        {error, invalid_key} ->
            {404, [], #{reason => <<"Invalid key">>}};
        {error, account_not_found} ->
            {404, [], #{reason => <<"Account not found">>}};
        {error, key_not_found} ->
            {404, [], #{reason => <<"Keys not configured">>}}
    end;

handle_request('PostOracleResponseTx', #{'OracleResponseTx' := OracleResponseTxObj}, _Context) ->
    #{<<"query_id">> := EncodedQueryId,
      <<"response">> := Response,
      <<"fee">>      := Fee} = OracleResponseTxObj,
    TTL = maps:get(<<"ttl">>, OracleResponseTxObj, 0),
    case aec_base58c:safe_decode(oracle_query_id, EncodedQueryId) of
        {ok, DecodedQueryId} ->
            case aehttp_int_tx_logic:oracle_response(DecodedQueryId, Response,
                                                     Fee, TTL) of
                {ok, Tx} ->
                    {_, TxHash} = aehttp_int_tx_logic:sender_and_hash(Tx),
                    {200, [], #{query_id => EncodedQueryId,
                                tx_hash => aec_base58c:encode(tx_hash, TxHash)}};
                {error, account_not_found} ->
                    {404, [], #{reason => <<"Account not found">>}};
                {error, key_not_found} ->
                    {404, [], #{reason => <<"Keys not configured">>}}
            end;
        {error, _} ->
            {404, [], #{reason => <<"Invalid Query Id">>}}
    end;

handle_request('GetNodePubkey', _, _Context) ->
    case aec_keys:pubkey() of
        {ok, Pubkey} ->
            %% TODO: rename pub_key to pubkey
            {200, [], #{pub_key => aec_base58c:encode(account_pubkey, Pubkey)}};
        {error, key_not_found} ->
            {404, [], #{reason => <<"Public key not found">>}}
    end;

handle_request('GetCommitmentId', Req, _Context) ->
    Name         = maps:get('name', Req),
    Salt         = maps:get('salt', Req),
    case aens:get_commitment_hash(Name, Salt) of
        {ok, CHash} ->
            EncodedCHash = aec_base58c:encode(commitment, CHash),
            {200, [], #{commitment_id => EncodedCHash}};
        {error, Reason} ->
            ReasonBin = atom_to_binary(Reason, utf8),
            {400, [], #{reason => <<"Name validation failed with a reason: ", ReasonBin/binary>>}}
    end;

handle_request('GetPendingTransactions', _Req, _Context) ->
    {ok, Txs} = aec_tx_pool:peek(infinity),
    {200, [], #{transactions => [aetx_sign:serialize_for_client_pending(T) || T <- Txs]}};

handle_request('GetPeers', _Req, _Context) ->
    case aeu_env:user_config_or_env([<<"http">>, <<"debug">>],
                                    aehttp, enable_debug_endpoints, false) of
        true ->
            Peers = aehttp_logic:connected_peers(all),
            InboundPeers = aehttp_logic:connected_peers(inbound),
            OutboundPeers = aehttp_logic:connected_peers(outbound),
            Blocked = aehttp_logic:blocked_peers(),

            {200, [], #{peers => lists:map(fun aec_peers:encode_peer_address/1, Peers),
                        inbound => lists:map(fun aec_peers:encode_peer_address/1, InboundPeers),
                        outbound => lists:map(fun aec_peers:encode_peer_address/1, OutboundPeers),
                        blocked => lists:map(fun aec_peers:encode_peer_address/1, Blocked)}};
        false ->
            {403, [], #{reason => <<"Call not enabled">>}}
    end;

handle_request(OperationID, Req, Context) ->
    error_logger:error_msg(
      ">>> Got not implemented request to process: ~p~n",
      [{OperationID, Req, Context}]
     ),
    {501, [], #{}}.

