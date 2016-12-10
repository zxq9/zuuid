%%% @doc
%%% zUUID state manager process.
%%%
%%% This process manages the state of time-based generation data for UUID
%%% versions 1 and 2 and implements measures to prevent generation of
%%% duplicate UUIDs in the case of very high frequency calls to {@link zuuid:v1/0},
%%% {@link zuuid:v2/0} or {@link zuuid:v2/1}.
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
%%% process has started by using {@link zuuid:config/1}.
%%% @end

-module(zuuid_man).
-author("Craig Everett <zxq9@zxq9.com>").
-behavior(gen_server).

-export([config/1, start_link/0, check_offset/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).


%%% State record

-record(s, {clock_seq = random_clock() :: zuuid:clock_seq(),
            clock_adj = 1              :: non_neg_integer(),
            node      = random_mac()   :: zuuid:ieee802mac(),
            posix_id  = random_uid()   :: zuuid:posix_id(),
            local_id  = random_lid()   :: zuuid:local_id(),
            last_v1   = zuuid:nil()    :: zuuid:uuid(),
            last_v2   = zuuid:nil()    :: zuuid:uuid()}).


%%% Types

-type state() :: #s{}.


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



%%% Interface

-spec config(Value) -> Result
    when Value  :: {clock_seq, random | zuuid:clock_seq()}
                 | {node,      random | zuuid:ieee802mac() | bad_mac}
                 | {posix_id,  random | zuuid:posix_id()}
                 | {local_id,  random | zuuid:local_id()},
         Result :: ok
                 | {error, Reason},
         Reason :: bad_mac.
%% @private
%% Allows zuuid application to be configured after startup with any desired
%% values that would affect generation of version 1 or 2 UUIDs (versions 3, 4
%% and 5 do not use system state information to generate their result).
%%
%% Accepts a value of `{node, bad_mac}' to permit compositions of the
%% following form without crashing the state management process on bad
%% input:
%% ```
%% zuuid:config({node, zuuid:read_mac(SomeString)})
%% '''
%%
%% This function accepts only explicit attribute arguments as a filter to crash
%% the caller in the event of an illegal call instead of crashing this state manager.
%%
%% NOTE: The export from this module should not be called directly.
%%       Use zuuid:config/1 instead.
%% @see zuuid:config/1.

config({clock_seq, Value}) ->
    gen_server:cast(?MODULE, {config, {clock_seq, Value}});
config({node, bad_mac}) ->
    {error, bad_mac};
config({node, Value}) ->
    gen_server:cast(?MODULE, {config, {node, Value}});
config({posix_id, Value}) ->
    gen_server:cast(?MODULE, {config, {posix_id, Value}});
config({local_id, Value}) ->
    gen_server:cast(?MODULE, {config, {local_id, Value}}).


%%% Startup

-spec start_link() -> {ok, pid()} | {error, term()}.
%% @private
%% Startup function -- intended to be called by zuuid_sup.
%%
%% Error conditions are documented in the gen_server module:
%% http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/gen_server.html#start_link-4

start_link() ->
    start_link(none).


-spec start_link(none) -> {ok, pid()} | {error, term()}.
%% @private
%% Alternative pre-configured startup, currently only ever passed 'none' as an argument.
%%
%% Error conditions are documented in the gen_server module:
%% http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/gen_server.html#start_link-4

start_link(Args) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).


-spec init(term()) -> {ok, state()}.
%% @doc
%% gen_server callback for startup.
%%
%% zuuid_man initializes every time with a randomized internal state for
%% generation of version 1 and 2 UUIDs. Users are advised to configure
%% the uuid state manager after startup to customize the state if desired.
%% @see zuuid:config/1.

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
%% Replace this clause with a call to a logger if your system is using one. In most
%% cases the following call to io:format/2 will go nowhere (STDOUT is probably not
%% connected to anything useful).
handle_call(Unexpected, From, State) ->
    ok = io:format("~p: Unexpected call from ~p: ~tp~n", [self(), From, Unexpected]),
    {noreply, State}.


%% @private
%% Should only be receiving casts generated by zuuid:config/1 -- anything else should
%% drop a notification.
handle_cast({config, Value}, State) ->
    NewState = do_config(Value, State),
    {noreply, NewState};
%% Replace this clause with a call to a logger if your system is using one. In most
%% cases the following call to io:format/2 will go nowhere (STDOUT is probably not
%% connected to anything useful).
handle_cast(Unexpected, State) ->
    ok = io:format("~p: Unexpected cast: ~tp~n", [self(), Unexpected]),
    {noreply, State}.


%% @private
%% Normally this process should not be receiving any non-OTP messages.
%% Replace this clause with a call to a logger if your system is using one. In most
%% cases the following call to io:format/2 will go nowhere (STDOUT is probably not
%% connected to anything useful).
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
    when State    :: state(),
         UUID     :: zuuid:uuid(),
         NewState :: state().
%% Generate a version 1 UUID in accordance with RFC 4122.
%% (http://www.ietf.org/rfc/rfc4122.txt)
%%
%% This function checks that the last generated value is not the same as the current
%% one (single-history duplicate detection), generating a new one with an updated
%% clock sequence if it is.

v1(State = #s{clock_seq = Seq, clock_adj = Adj, node = Node, last_v1 = Last}) ->
    case gen_v1(Seq, Node) of
        Last = {uuid, <<Pref:66, _:62>>} ->
            UUID = {uuid, <<Pref:66, (Seq + Adj):14, Node/binary>>},
            {UUID, State#s{clock_adj = Adj + 1, last_v1 = UUID}};
        UUID ->
            {UUID, State#s{clock_adj = 1, last_v1 = UUID}}
    end.


-spec gen_v1(zuuid:clock_seq(), <<_:48>>) -> zuuid:uuid().
%% Assembly of version 1 UUID.

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
         State    :: state(),
         UUID     :: zuuid:uuid(),
         NewState :: state().
%% Generate a version 2 (DEC Security) UUID using stored ID values.
%%
%% This function checks that the last generated value is not the same as the current
%% one (single-history duplicate detection), generating a new one with an updated
%% clock sequence if it is.

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
%% Assembly of version 2 UUID.

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

-spec do_config(Value, State) -> NewState
    when Value    :: {clock_seq, random | zuuid:clock_seq()}
                   | {node,      random | zuuid:ieee802mac()}
                   | {posix_id,  random | zuuid:posix_id()}
                   | {local_id,  random | zuuid:local_id()},
         State    :: state(),
         NewState :: state().

do_config({Attribute, random}, State) ->
    case Attribute of
        clock_seq -> State#s{clock_seq = random_clock()};
        node      -> State#s{node      = random_mac()};
        posix_id  -> State#s{posix_id  = random_uid()};
        local_id  -> State#s{local_id  = random_lid()};
        _         -> State
    end;
do_config({clock_seq, Seq}, State) ->
    State#s{clock_seq = Seq};
do_config({node, MAC}, State) ->
    State#s{node = MAC};
do_config({posix_id, ID}, State) ->
    State#s{posix_id = ID};
do_config({local_id, ID}, State) ->
    State#s{local_id = ID};
do_config(_, State) ->
    State.



%%% Utilities

-spec check_offset() -> true.
%% @doc
%% An explanation and hard-coded test of the magic constant macro ?OFFSET,
%% which defines the difference in nanoseconds between the RFC 4122 accounting
%% date for UUID generation and the beginning of the Unix epoch.

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





-spec random_mac() -> zuuid:ieee802mac().
%% @private
%% Generate a random IEEE 802 MAC address in compliance with RFC 4122.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time. The IEEE 802 broadcast-bit is set on MAC
%% addresses returned by this function, so they should never collide with
%% actual addresses pulled from hardware components.
%%
%% To convert a hardware address in hex string notation use `read_mac/1'.

random_mac() ->
    <<A:7, _:1, B:40>> = crypto:strong_rand_bytes(6),
    BroadcastBit = 1, % RFC 4122 requires this be set for randomized MACs
    <<A:7, BroadcastBit:1, B:40>>.


-spec random_clock() -> zuuid:clock_seq().
%% @private
%% Generate a random 14-bit clock sequence.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_clock() ->
    <<_:2, ClockSeq:14>> = crypto:strong_rand_bytes(2),
    ClockSeq.


-spec random_uid() -> zuuid:posix_id().
%% @private
%% Generate a random 4-byte value for use as POSIX UID in version 2 UUID generation.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_uid() ->
    <<ID:32>> = crypto:strong_rand_bytes(4),
    ID.


-spec random_lid() -> zuuid:local_id().
%% @private
%% Generate a random 8-bit value for use as POSIX Group/Local ID value for use
%% in version 2 UUID generation.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_lid() ->
    <<ID:8>> = crypto:strong_rand_bytes(1),
    ID.
