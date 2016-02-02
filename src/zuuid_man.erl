%%% @doc
%%% zUUID state manager process.
%%%
%%% This process manages the state of time-based generation data for UUID
%%% versions 1 and 2 and implements measures to prevent generation of
%%% duplicate UUIDs in the case of very high frequency calls to zuuid:v1()
%%% or zuuid:v2
%%%
%%% Starting the zUUID application with zuuid:start/0 is not necessary if only
%%% using version 3, 4 or 5 UUIDs, or for using the UUID manipulation functions
%%% in the uuid module.
%%%
%%% On startup this process will initialize itself with random data for the
%%% clock sequence, node/MAC address, posix UID and posix location/GID values.
%%% If custom values are desired for any of these state attributes (such as
%%% the actual primary MAC address used by the machine, actual posix UID, or
%%% some other deliberate identifying data) they can be set after this
%%% process has started by using zuuid:config/1.
%%%
%%% @see zuuid:config/1.
%%% @end

-module(zuuid_man).
-behavior(gen_server).
-export([start_link/0, check_offset/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).


%%% State record
-record(s, {clock_seq = zuuid:random_clock() :: zuuid:clock_seq(),
            clock_adj = 1                    :: non_neg_integer(),
            node      = zuuid:random_mac()   :: zuuid:ieee802mac(),
            posix_id  = zuuid:random_uid()   :: zuuid:posix_id(),
            local_id  = zuuid:random_lid()   :: zuuid:local_id(),
            last_v1   = zuuid:nil()          :: zuuid:uuid(),
            last_v2   = zuuid:nil()          :: zuuid:uuid()}).


%%% Constants

% From RFC 4122:
% ```
% 4.1.4.  Timestamp
%  The timestamp is a 60-bit value.  For UUID version 1, this is
%  represented by Coordinated Universal Time (UTC) as a count of 100-
%  nanosecond intervals since 00:00:00.00, 15 October 1582 (the date of
%  Gregorian reform to the Christian calendar).
% '''
% For a more detailed explanation of this magical constant,
% see definition of check_offset/0.
-define(OFFSET, 122192928000000000).


%%% Startup

%% @doc
%% @private
%% Startup function -- intended to be called by zuuid_sup.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(none).

%% @doc
%% @private
%% Alternative pre-configured startup, currently only ever passed 'none'
%% as an argument.
-spec start_link(none) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

%% @doc
%% gen_server callback for startup.
%%
%% zuuid_man initializes every time with a randomized internal state for
%% generation of version 1 and 2 UUIDs. Users are advised to configure
%% the uuid state manager after startup to customize the state if desired.
%% @see zuuid:config/1.
-spec init(term()) -> {ok, term()}.
init(_) ->
    {ok, #s{}}.


%%% gen_server

%% @private
handle_call(v1, _, State) ->
    {Result, NewState} = v1(State),
    {reply, Result, NewState};
handle_call(v2, _, State = #s{posix_id = PosixID, local_id = LocalID}) ->
    {Result, NewState} = v2(PosixID, LocalID, State),
    {reply, Result, NewState};
handle_call({v2, PosixID, LocalID}, _, State) ->
    {Result, NewState} = v2(PosixID, LocalID, State),
    {reply, Result, NewState};
handle_call(Unexpected, From, State) ->
    ok = io:format("~p: Unexpected call from ~p: ~tp~n", [self(), From, Unexpected]),
    {noreply, State}.

%% @private
handle_cast({config, Value}, State) ->
    NewState = config(Value, State),
    {noreply, NewState};
handle_cast(Unexpected, State) ->
    ok = io:format("~p: Unexpected cast: ~tp~n", [self(), Unexpected]),
    {noreply, State}.

%% @private
handle_info(Unexpected, State) ->
    ok = io:format("~p: Unexpected info: ~tp~n", [self(), Unexpected]),
    {noreply, State}.

%% @private
terminate(_, _) ->
    ok.

%% @private
code_change(_, State, _) ->
    {ok, State}.


%%% UUID generation

%% V1
-spec v1(State) -> {UUID, NewState}
    when State    :: #s{},
         UUID     :: zuuid:uuid(),
         NewState :: #s{}.
v1(State = #s{clock_seq = Seq, clock_adj = Adj, node = Node, last_v1 = Last}) ->
    case gen_v1(Seq, Node) of
        Last = {uuid, <<Pref:66, _:62>>} ->
            UUID = {uuid, <<Pref:66, (Seq + Adj):14, Node/binary>>},
            {UUID, State#s{clock_adj = Adj + 1, last_v1 = UUID}};
        UUID ->
            {UUID, State#s{clock_adj = 1, last_v1 = UUID}}
    end.

-spec gen_v1(zuuid:clock_seq(), <<_:48>>) -> zuuid:uuid().
gen_v1(ClockSeq, Node) ->
    GregorianInterval = ?OFFSET + erlang:system_time(nano_seconds) div 100,
    <<High:12, Mid:16, Low:32>> = <<GregorianInterval:60>>,
    Variant = 2,  % Indicates RFC 4122
    Version = 1,  % UUID version number
    {uuid, <<Low:32, Mid:16, Version:4, High:12, Variant:2, ClockSeq:14, Node/binary>>}.


%% V2
-spec v2(PosixID, LocalID, State) -> {UUID, NewState}
    when PosixID  :: zuuid:posix_id(),
         LocalID  :: zuuid:local_id(),
         State    :: #s{},
         UUID     :: zuuid:uuid(),
         NewState :: #s{}.
v2(PosixID,
   LocalID,
   State = #s{clock_seq = Seq, clock_adj = Adj, node = Node, last_v2 = Last}) ->
    case gen_v2(PosixID, LocalID, Seq, Node) of
        Last = {uuid, <<Pref:74, _:54>>} ->
            <<_:8, Adjusted:6>> = <<(Seq + Adj):14>>,
            UUID = {uuid, <<Pref:74, Adjusted:6, Node/binary>>},
            {UUID, State#s{clock_adj = Adj + 1, last_v2 = UUID}};
        UUID ->
            {UUID, State#s{clock_adj = 1, last_v2 = UUID}}
    end.

-spec gen_v2(PosixID, LocalID, ClockSeq, MAC) -> UUID
    when PosixID  :: zuuid:posix_id(),
         LocalID  :: zuuid:local_id(),
         ClockSeq :: zuuid:clock_seq(),
         MAC      :: zuuid:ieee802mac(),
         UUID     :: zuuid:uuid().
gen_v2(PosixID, LocalID, ClockSeq, Node) ->
    GregorianInterval = ?OFFSET + erlang:system_time(nano_seconds) div 100,
    <<_:32, Time:28>> = <<GregorianInterval:60>>,
    <<PosixA:20, PosixB:12>> = <<PosixID:32>>,
    <<_:8, Seq:6>> = <<ClockSeq:14>>,
    Variant = 2,  % Indicates RFC 4122
    Version = 2,  % UUID version number
    {uuid, <<Time:28, PosixA:20, Version:4,
                      PosixB:12, Variant:2, LocalID:8, Seq:6, Node/binary>>}.


%%% State Configuration

-spec config(Value, State) -> NewState
    when Value    :: {clock_seq, random | zuuid:clock_seq()}
                   | {node,      random | zuuid:ieee802mac()}
                   | {posix_id,  random | zuuid:posix_id()}
                   | {local_id,  random | zuuid:local_id()},
         State    :: #s{},
         NewState :: #s{}.
config({Attribute, random}, State) ->
    case Attribute of
        clock_seq -> State#s{clock_seq = zuuid:random_clock()};
        node      -> State#s{node = zuuid:random_mac()};
        posix_id  -> State#s{posix_id = zuuid:random_uid()};
        local_id  -> State#s{local_id = zuuid:random_lid()};
        _         -> State
    end;
config({clock_seq, Seq}, State) ->
    State#s{clock_seq = Seq};
config({node, MAC}, State) ->
    State#s{node = MAC};
config({posix_id, ID}, State) ->
    State#s{posix_id = ID};
config({local_id, ID}, State) ->
    State#s{local_id = ID};
config(_, State) ->
    State.


%%% Utilities

%% @doc
%% An explanation and hard-coded test of the magic constant macro ?OFFSET,
%% which defines the difference in nanoseconds between the RFC 4122 accounting
%% date for UUID generation and the beginning of the Unix epoch.
-spec check_offset() -> true.
check_offset() ->
    Greg = calendar:datetime_to_gregorian_seconds({{1582, 10, 15}, {0, 0, 0}}),
    Unix = calendar:datetime_to_gregorian_seconds({{1970, 01, 01}, {0, 0, 0}}),
    Interval = Unix - Greg,
    Offset = Interval * 10000000,
    ok = io:format("Seconds from 0AD to 1582-10-15T00:00:00Z: ~p~n"
                   "Seconds from 0AD to 1970-01-01T00:00:00Z: ~p~n"
                   "Interval between 1582-10-15 and 1970-01-01 in seconds: ~p~n"
                   "Offset interval in nanoseconds: ~p~n",
                   [Greg, Unix, Interval, Offset]),
    ?OFFSET == Offset.

