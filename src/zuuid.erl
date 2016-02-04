%%% @doc
%%% RFC-4122 UUID generator and manipulator.
%%%
%%% This is the interface module and application file for zUUID. To generate
%%% version 1 or 2 UUIDs the uuid application must be started by calling
%%% {@link zuuid:start/0} first. After the application is started {@link zuuid:config/1}
%%% can be used to set arbitrary state values on the state manager like the node/MAC
%%% address, POSIX IDs, and so on.
%%%
%%% @see zuuid:start/0.
%%% @see zuuid:config/1.
%%% @end

-module(zuuid).
-author("Craig Everett <zxq9@zxq9.com>").
-behavior(application).

-export([start/0, config/1, stop/0]).
-export([start/2, stop/1]).
-export([v1/0,
         v2/0, v2/2,
         v3/1, v3/2, v3rand/1,
         v4/0,
         v5/1, v5/2, v5rand/1,
         nil/0,
         read_uuid/1, read_mac/1, version/1,
         string/1, string/2,
         binary/1, binary/2,
         get_hw_addr/0, get_hw_addr/1,
         random_mac/0, random_clock/0, random_uid/0, random_lid/0]).


%%% Side-effect free

-pure([v3/1, v3/2, v3_hash/2, v5/1, v5/2, v5_hash/2,
       read_uuid/1, read_uuid_string/1, read_mac/1, read_mac_string/1,
       string/1, string/2,
       binary/1, binary/2,
       strhexs_to_uuid/1, strhexs_to_mac/1,
       strhexs_to_integers/1, bins_to_strhexs/1, binary_to_strhex/1]).


%%% Types

-export_type([uuid/0, ieee802mac/0, clock_seq/0, posix_id/0, local_id/0]).

-type uuid()       :: {uuid, <<_:128>>}.
-type ieee802mac() :: <<_:48>>.
-type clock_seq()  :: non_neg_integer().  % Becomes `<<_:14>>'.
-type posix_id()   :: non_neg_integer().  % Becomes `<<_:32>>'.
-type local_id()   :: non_neg_integer().  % Becomes `<<_:8>>'.
-type hexchar()    :: 48..57              % ASCII ranges: '0' - '9'
                    | 65..70              %               'A' - 'F'
                    | 97..102.            %               'a' - 'f'
-type strhex()     :: [hexchar()].
-type namespace()  :: nil | url | dns | oid | x500.


%%% Constants

%% RFC 4122 Appendix C namespace IDs
%% http://tools.ietf.org/html/rfc4122#appendix-C
% 6ba7b810-9dad-11d1-80b4-00c04fd430c8
-define(DNS_NS,  <<107,167,184,16,157,173,17,209,128,180,0,192,79,212,48,200>>).
% 6ba7b811-9dad-11d1-80b4-00c04fd430c8
-define(URL_NS,  <<107,167,184,17,157,173,17,209,128,180,0,192,79,212,48,200>>).
% 6ba7b812-9dad-11d1-80b4-00c04fd430c8
-define(OID_NS,  <<107,167,184,18,157,173,17,209,128,180,0,192,79,212,48,200>>).
% 6ba7b814-9dad-11d1-80b4-00c04fd430c8
-define(X500_NS, <<107,167,184,20,157,173,17,209,128,180,0,192,79,212,48,200>>).


%%% Application services

-spec start() -> ok.
%% @doc
%% Starts the zuuid application, spawning a supervisor and a worker to manage
%% state generation details for version 1 and 2 UUIDs and ensure duplicates
%% will not occur even at high call frequencies (as suggested in
%% <a href="http://tools.ietf.org/html/rfc4122#section-4.2.1">RFC 4122, 4.2.1</a>).
%%
%% It is not necessary to start the application for UUID versions 3, 4 or 5
%% (versions 3 and 5 are actually pure functions, while 4 has only the side effect
%% of calling `crypto:strong_rand_bytes/1').

start() ->
    application:start(?MODULE, permanent).


-spec stop() -> ok.
%% @doc
%% Stops the zuuid application.

stop() ->
    application:stop(?MODULE).


-spec config(Value) -> Result
    when Value  :: {clock_seq, random | clock_seq()}
                 | {node,      random | ieee802mac() | bad_mac}
                 | {posix_id,  random | posix_id()}
                 | {local_id,  random | local_id()},
         Result :: ok
                 | {error, Reason},
         Reason :: bad_mac.
%% @doc
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
%% @see zuuid:read_mac/1.

config({node, bad_mac}) ->
    {error, bad_mac};
config(Value) ->
    gen_server:cast(zuuid_man, {config, Value}).


-spec start(normal, term()) -> {ok, pid()}.
%% @doc
%% @private
%% Application behavior callback.
%%
%% Do not call this function. It only accepts `normal' as a start type and
%% disregards any starting arguments.

start(normal, Args) ->
    zuuid_sup:start_link(Args).


-spec stop(term()) -> ok.
%% @doc
%% @private
%% Application behavior callback.
%%
%% Stops the application, disregarding any arguments and performing no
%% spin-down tasks.

stop(_) ->
    ok.


%%% UUID Utility Interface

-spec v1() -> uuid().
%% @doc
%% Generate an RFC 4122 version 1 UUID.
%%
%% This function requires that the zuuid application be started before
%% being called. The process zuuid_man maintains a record of UUID generation
%% and implements measures to ensure that generation on very fast systems
%% will not produce duplicate clock-based UUIDs by mistake.
%%
%% The UUIDs generated by this function are based on the state of the
%% generator process at the time it is called. The state (MAC address,
%% clock sequence, etc.) can be updated by calling config/1.

v1() ->
    gen_server:call(zuuid_man, v1).


-spec v2() -> uuid().
%% @doc
%% Generate an RFC 4122 version 2 (DEC Security) UUID with current ID values.
%%
%% This function requires that the zuuid application be started before
%% being called. The process zuuid_man maintains a record of UUID generation
%% and implements measures to ensure that generation on very fast systems
%% will not produce duplicate clock-based UUIDs by mistake.
%%
%% DEC Security UUID generation is not explicitly referenced in RFC 4122,
%% but the process is similiar to version 1 UUIDs with the exception that
%% some clock and clock sequence bits are replaced with Posix user and
%% local/group ID data. The UUIDs generated by this function are based
%% on the state of the generator process at the time it is called. The state
%% (MAC address, Posix user and local/group IDs, clock sequence, etc.) can be
%% updated by calling config/1.

v2() ->
    gen_server:call(zuuid_man, v2).


-spec v2(posix_id(), local_id()) -> uuid().
%% @doc
%% Generate an RFC 4122 version 2 (DEC Security) UUID with custom ID values.
%% 
%% This function requires that the zuuid application be started before
%% being called.
%%
%% This function is like v2/0, but allows supplying the Posix ID values
%% without reconfiguring the UUID generator process.

v2(PosixID, LocalID) ->
    gen_server:call(zuuid_man, {v2, PosixID, LocalID}).


-spec v3(iodata()) -> uuid().
%% @equiv v3(nil, Name)

v3(Name) ->
    v3(nil, Name).


-spec v3(Prefix, Name) -> uuid()
    when Prefix :: namespace()
                 | iodata(),
         Name   :: iodata().
%% @doc
%% Generate an RFC 4122 version 3 UUID (md5 hash).
%%
%% This function provides atom values for RFC 4122 appendix C namespaces,
%% a nil namespace (direct hash over single argument), and any arbitrary
%% namespace.
%%
%% Calling `v3(Name)' is the same as calling `v3(nil, Name)'.

v3(nil, Name) ->
    <<A:48, _:4, B:12, _:2, C:62>> = crypto:hash(md5, Name),
    Variant = 2,  % Indicates RFC 4122
    Version = 3,  % UUID version number
    {uuid, <<A:48, Version:4, B:12, Variant:2, C:62>>};
v3(url, Name) ->
    v3_hash(?URL_NS, Name);
v3(dns, Name) ->
    v3_hash(?DNS_NS, Name);
v3(oid, Name) ->
    v3_hash(?OID_NS, Name);
v3(x500, Name) ->
    v3_hash(?X500_NS, Name);
v3(Data, Name) ->
    v3_hash(Data, Name).


-spec v3rand(iodata()) -> uuid().
%% @equiv zuuid:v3(crypto:strong_rand_bytes(16), Name)

v3rand(Name) ->
    v3_hash(crypto:strong_rand_bytes(16), Name).


-spec v3_hash(iodata(), iodata()) -> uuid().

v3_hash(Z, X) ->
    <<A:48, _:4, B:12, _:2, C:62>> = crypto:hash(md5, [Z, X]),
    Variant = 2,  % Indicates RFC 4122
    Version = 3,  % UUID version number
    {uuid, <<A:48, Version:4, B:12, Variant:2, C:62>>}.


-spec v4() -> uuid().
%% @doc
%% Generate an RFC 4122 version 4 UUID (strongly random UUID).
%%
%% This function calls `crypto:strong_rand_bytes/1'. There is a very small
%% chance the call could fail with an exception `low_entropy' if your program
%% calls it at very high speed and your systems random device cannot keep up.
%% So far in testing on Linux and BSD this has not been a problem, even
%% generating hundreds of thousands of UUIDs to populate a database, but it
%% could happen. If this call fails the caller will crash if it does not catch
%% the exception.

v4() ->
    <<A:48, _:4, B:12, _:2, C:62>> = crypto:strong_rand_bytes(16),
    Variant = 2,  % Indicates RFC 4122
    Version = 4,  % UUID version number
    {uuid, <<A:48, Version:4, B:12, Variant:2, C:62>>}.


-spec v5(iodata()) -> uuid().
%% @equiv v5(nil, Name)

v5(Name) ->
    v5(nil, Name).


-spec v5(Prefix, Name) -> uuid()
    when Prefix :: namespace()
                 | iodata(),
         Name   :: iodata().
%% @doc
%% Generate an RFC 4122 version 5 UUID (truncated sha1 hash).
%%
%% This function provides atom values for RFC 4122 appendix C namespaces,
%% a nil namespace (direct hash over single argument), and any arbitrary
%% namespace.

v5(nil, Name) ->
    v5_hash(<<0:128>>, Name);
v5(url, Name) ->
    v5_hash(?URL_NS, Name);
v5(dns, Name) ->
    v5_hash(?DNS_NS, Name);
v5(oid, Name) ->
    v5_hash(?OID_NS, Name);
v5(x500, Name) ->
    v5_hash(?X500_NS, Name);
v5(Data, Name) ->
    v5_hash(Data, Name).


-spec v5rand(iodata()) -> uuid().
%% @doc
%% Generate an RFC 4122 version 5 UUID (truncated sha1 hash) with a random
%% namespace.
%% @equiv zuuid:v5(crypto:strong_rand_bytes(16), Name)

v5rand(Name) ->
    v5_hash(crypto:strong_rand_bytes(16), Name).


-spec v5_hash(iodata(), iodata()) -> uuid().

v5_hash(Z, X) ->
    <<A:48, _:4, B:12, _:2, C:62, _:32>> = crypto:hash(sha, [Z, X]),
    Variant = 2,  % Indicates RFC 4122
    Version = 5,  % UUID version number
    {uuid, <<A:48, Version:4, B:12, Variant:2, C:62>>}.


-spec nil() -> uuid().
%% @doc
%% Generate an RFC 4122 nil UUID.

nil() ->
    {uuid, <<0:128>>}.


-spec read_uuid(Input) -> Result
    when Input  :: uuid()
                 | string()
                 | binary(),
         Result :: uuid()
                 | bad_uuid.
%% @doc
%% Takes serialized representation of a UUID/GUID in a variety of formats
%% and returns an internalized representation or the atom 'bad_uuid' in
%% the case of malformed input.
%%
%% Given a UUID "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
%% acceptable input representations are:
%% ```
%% "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}"
%% "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
%% "{6BA7B8109DAD11D180B400C04FD430C8}"
%% "6ba7b8109dad11d180b400c04fd430c8"
%% <<"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}">>
%% <<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>
%% <<"{6BA7B8109DAD11D180B400C04FD430C8}">>
%% <<"6ba7b8109dad11d180b400c04fd430c8">>
%% {uuid,<<107,167,184,16,157,173,17,209,128,180,0,192,79,212,48,200>>}
%% <<107,167,184,16,157,173,17,209,128,180,0,192,79,212,48,200>>
%% '''
%% Hexadecimal "letter" values are not case sensitive.

read_uuid(UUID = <<_:128>>) ->
    {uuid, UUID};
read_uuid(UUID) when is_binary(UUID) ->
    read_uuid_string(binary_to_list(UUID));
read_uuid(UUID) when is_list(UUID) ->
    read_uuid_string(UUID);
read_uuid(UUID = {uuid, <<_:128>>}) ->
    UUID;
read_uuid(_) ->
    bad_uuid.


-spec read_uuid_string(string()) -> uuid() | bad_uuid.

read_uuid_string(UUID) ->
    Parts = string:tokens(UUID, "{-}"),
    case [length(Part) || Part <- Parts] of
        [8, 4, 4, 4, 12] -> strhexs_to_uuid(Parts);
        [32]             -> strhexs_to_uuid(Parts);
        _                -> bad_uuid
    end.


-spec read_mac(Input) -> Result
    when Input  :: string()
                 | binary(),
         Result :: ieee802mac()
                 | bad_mac.
%% @doc
%% Takes a serialized representation of an IEEE 802 MAC address in a variety of
%% formats and returns an internalized representation (currently a 48-bit binary)
%% or the atom 'bad_mac' in the case of malformed input.
%%
%% Given a MAC "12:34:56:78:90:AB", acceptable input representations are:
%% ```
%% "12:34:56:78:90:AB"
%% "12-34-56-78-90-ab"
%% "12.34.56.78.90.ab"
%% "1234567890AB"
%% <<"12:34:56:78:90:ab">>
%% <<"12-34-56-78-90-AB">>
%% <<"12.34.56.78.90.ab">>
%% <<"1234567890ab">>
%% '''
%% 64-bit hardware addresses (EUI-64 addresses) are also accepted, but are adjusted
%% to 48-bit length before being returned as a MAC. In the case of MAC-48 or EUI-48
%% to EUI-64 address conversion, the original MAC-48/EUI-48 address is returned. In
%% the case of assembled EUI-64 or native EUI-64 bit addresses, the last two bytes
%% are truncated.
%% 
%% MAC-48/EUI-48 "12-34-56-78-90-AB" to EUI-64:
%% ```
%% "12-34-56-FF-FE-78-90-AB"
%% "123456fffe7890ab"
%% <<18,52,86,255,254,120,144,171>>
%% '''
%% Returns: `<<18,52,86,120,144,171>>'
%%
%% Native EUI-64:
%% ```
%% "12-34-56-78-90-AB-CD-EF"
%% "1234567890abcdef"
%% <<18,52,86,120,144,171,205,239>>
%% '''
%% Returns: `<<18,52,86,120,144,171>>'
%%
%% Hexadecimal "letter" values are not case sensitive.

read_mac(MAC = <<_:12/binary>>) ->
    read_mac_string(binary_to_list(MAC));
read_mac(MAC = <<_:16/binary>>) ->
    read_mac_string(binary_to_list(MAC));
read_mac(MAC = <<_:17/binary>>) ->
    read_mac_string(binary_to_list(MAC));
read_mac(MAC = <<_:23/binary>>) ->
    read_mac_string(binary_to_list(MAC));
read_mac(MAC = <<_:48>>) ->
    MAC;
read_mac(<<A:24, 255, 254, B:24>>) ->
    <<A:24, B:24>>;
read_mac(<<MAC:48, _:16>>) ->
    <<MAC:48>>;
read_mac(MAC) when is_list(MAC) ->
    read_mac_string(MAC);
read_mac(_) ->
    bad_mac.


-spec read_mac_string(string()) -> ieee802mac() | bad_mac.

read_mac_string(MAC) ->
    Parts = case string:tokens(string:to_upper(MAC), ":-.") of
        [A,B,C,"FF","FE",D,E,F]                 -> [A,B,C,D,E,F];
        [[A,B,C,D,E,F,$F,$F,$F,$E,G,H,I,J,K,L]] -> [[A,B,C,D,E,F,G,H,I,J,K,L]];
        Tokens                                  -> Tokens
    end,
    case [length(Part) || Part <- Parts] of
        [2, 2, 2, 2, 2, 2] ->
            strhexs_to_mac(Parts);
        [2, 2, 2, 2, 2, 2, 2, 2] ->
            strhexs_to_mac(lists:sublist(Parts, 6));
        [12] ->
            strhexs_to_mac(Parts);
        [16] ->
            [String] = Parts,
            strhexs_to_mac([lists:sublist(String, 12)]);
        _ ->
            bad_mac
    end.


-spec version(UUID) -> VarVer
    when UUID    :: uuid()
                  | term(),
         VarVer  :: {Variant, Version}
                  | bad_uuid,
         Variant :: rfc4122
                  | ncs
                  | microsoft
                  | reserved
                  | other,
         Version :: 1..5
                  | compatibility
                  | nil
                  | nonstandard.
%% @doc
%% Determine the variant and version of a UUID.
%%
%% Currently detects only RFC-4122 defined variant/versions.
%% Some homespun or wildly non-compliant 128-bit identifier values can
%% incidentally appear to comply with RFC-4122, so not all arguments are
%% guaranteed to return an accurate result.
%%
%% (Noncompliant values can be used by the rest of this module, though).
%%
%% Returns the atom 'bad_uuid' on non-UUID values, so composition with
%% {@link read_uuid/1} will return sane values on bad external input.

version({uuid, <<_:64, 0:1, _:63>>}) ->
    {ncs, compatibility};
version({uuid, <<_:48, V:4, _:12, 2:2, _:62>>})
        when 0 < V andalso V < 6 ->
    {rfc4122, V};
version({uuid, <<_:64, 6:3, _:61>>}) ->
    {microsoft, compatibility};
version({uuid, <<_:64, 7:3, _:61>>}) ->
    {reserved, nonstandard};
version({uuid, <<0:128>>}) ->
    {rfc4122, nil};
version({uuid, <<_:128>>}) ->
    {other, nonstandard};
version(_) ->
    bad_uuid.


-spec string(uuid()) -> string().
%% @deprecated Use {@link string/2} instead.
%% @equiv zuuid:string(UUID, brackets)

string(UUID) ->
    string(UUID, brackets).


-spec string(UUID, Format) -> Serialized
    when UUID       :: uuid(),
         Format     :: brackets
                     | standard
                     | no_break
                     | raw_bits,
         Serialized :: string().
%% @doc
%% Accept an internal UUID representation and return a canonical string
%% representation in one of three formats, or a string of 0's and 1's representing
%% each bit of the 128-bit value.
%%
%% For example:
%% ```
%% 1> zuuid:string(zuuid:read_uuid(<<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>), standard).
%% "6BA7B810-9DAD-11D1-80B4-00C04FD430C8"
%% 2> zuuid:string(zuuid:read_uuid(<<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>), brackets).
%% "{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}"
%% 3> zuuid:string(zuuid:read_uuid(<<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>), no_break).
%% "6BA7B8109DAD11D180B400C04FD430C8"
%% 4> zuuid:string(zuuid:read_uuid(<<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>), raw_bits).
%% "01101011101001111011100000010000100111011010110100010001110100011000000010110100000000001100000001001111110101000011000011001000"
%% '''

string({uuid, <<A:4/binary, B:2/binary, C:2/binary, D:2/binary, E:6/binary>>}, brackets) ->
    Parts = [{A, 8}, {B, 4}, {C, 4}, {D, 4}, {E, 12}],
    "{" ++ string:join(bins_to_strhexs(Parts), "-") ++ "}";
string({uuid, <<A:4/binary, B:2/binary, C:2/binary, D:2/binary, E:6/binary>>}, standard) ->
    Parts = [{A, 8}, {B, 4}, {C, 4}, {D, 4}, {E, 12}],
    string:join(bins_to_strhexs(Parts), "-");
string({uuid, Binary}, no_break) ->
    string:right(integer_to_list(binary:decode_unsigned(Binary), 16), 32, $0);
string({uuid, Binary}, raw_bits) ->
    string:right(integer_to_list(binary:decode_unsigned(Binary), 2), 128, $0).


-spec binary(uuid()) -> binary().
%% @deprecated Use {@link binary/2} instead.
%% @equiv zuuid:binary(UUID, brackets)

binary(UUID) ->
    binary(UUID, brackets).


-spec binary(UUID, Format) -> Serialized
    when UUID       :: uuid(),
         Format     :: brackets
                     | standard
                     | no_break
                     | raw_bits,
         Serialized :: binary().
%% @doc
%% Accept an internal UUID representation, and return a canonical binary
%% string representation in one of three formats, or raw bits as an Erlang term.
%%
%% For example:
%% ```
%% 1> zuuid:binary(zuuid:read_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"), standard).
%% <<"6BA7B810-9DAD-11D1-80B4-00C04FD430C8">>
%% 2> zuuid:binary(zuuid:read_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"), brackets).
%% <<"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}">>
%% 3> zuuid:binary(zuuid:read_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"), no_break).
%% <<"6BA7B8109DAD11D180B400C04FD430C8">>
%% 4> zuuid:binary(zuuid:read_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"), raw_bits).
%% <<107,167,184,16,157,173,17,209,128,180,0,192,79,212,48,200>>
%% '''

binary({uuid, Bits}, raw_bits) ->
    Bits;
binary(UUID, Format) ->
    list_to_binary(string(UUID, Format)).


%%% ID utilities

-spec get_hw_addr() -> Result
    when Result  :: {ok, Address}
                  | {error, Reason},
         Address :: <<_:48>>
                  | <<_:64>>,
         Reason  :: no_iface
                  | no_address
                  | inet:posix().
%% @doc
%% Attempt to retrieve the (or a) hardware address from the current machine.
%% 
%% This function will avoid returning the loopback address (0-0-0-0-0-0)
%% and may return either a 48-bit MAC or (in certain environments) a 64-bit
%% EUI address. Either value can be used to initialize the UUID state
%% manager to an actual hardware address on the machine. Because device
%% names are a function of the operating system there is no way to
%% guarantee that this function is deterministic. If you require a specific
%% address be used for generation of version 1 or 2 UUIDs it is safer to
%% present a known address in your own calling code.
%%
%% Example:
%% ```
%% ok = zuuid:start(),
%% MAC = case zuuid:get_hw_addr() of
%%     {ok, Addr} -> Addr;
%%     _          -> zuuid:random_mac()
%% end,
%% ok = zuuid:config({node, MAC}),
%% ...
%% '''
%% In the case that no interfaces are found, this function will return the value
%% {error, no_iface}. In the case that this function can locate interfaces, but
%% either no interfaces have an address or have an address other than 0.0.0.0
%% this function will return the value {error, no_address}.
%% @see zuuid:config/1.

get_hw_addr() ->
    case inet:getifaddrs() of
        {ok, []}         -> {error, no_iface};
        {ok, Interfaces} -> scan_hw_addr(Interfaces);
        Error            -> Error
    end.


scan_hw_addr([]) ->
    {error, no_address};
scan_hw_addr([{_, Info} | T]) ->
    case lists:keyfind(hwaddr, 1 , Info) of
        {hwaddr, [0,0,0,0,0,0]} -> scan_hw_addr(T);
        {hwaddr, MAC}           -> {ok, list_to_binary(MAC)};
        false                   -> scan_hw_addr(T)
    end.


-spec get_hw_addr(Name) -> Result
    when Name    :: string(),
         Result  :: {ok, Address}
                  | {error, Reason},
         Address :: <<_:48>>
                  | <<_:64>>,
         Reason  :: no_iface
                  | no_address
                  | inet:posix().
%% @doc
%% Attempt to retrieve the (or a) hardware address from a specific named
%% network interface.
%%
%% Works very similarly to get_hw_addr/0, but tries to retrieve an address
%% for a specific interface, and returns an error if the search fails. If
%% this function cannot find the named interface it will return {error, no_iface};
%% if it locates the interface but the named interface lacks an address or
%% has only the address 0.0.0.0 it will return {error, no_address}.
%%
%% Example:
%% ```
%% ok = zuuid:start(),
%% Try = ["eth2", "br1", "virbr0", "wlan0"],
%% MAC = case lists:keyfind(ok, 1, [zuuid:get_hw_addr(Z) || Z <- Try]) of
%%     {ok, Addr} -> Addr;
%%     false      -> zuuid:random_mac()
%% end,
%% ok = zuuid:config({node, MAC}),
%% ...
%% '''
%% The example above is of course extremely inefficient, but this should not
%% matter under normal circumstances where it will be called only once at
%% node startup. Environments where frequent node restarts are common (i.e.
%% client-side software) are better served by finding another way to identify
%% and store the desired hardware.
%%
%% NOTE: The addresses given above are "typical" addresses for a certain
%% category of unix-type system that uses the "eth0" naming convention. Other
%% naming conventions exist, such as the names used by
%% <a href="http://www.freedesktop.org/wiki/Software/systemd/PredictableNetworkInterfaceNames/">systemd/udev</a>,
%% (since v197),
%% <a href="https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/appe-Consistent_Network_Device_Naming.html">Fedora/RHEL</a>
%% (based on the systemd scheme),
%% <a href="http://www.juniper.net/techpubs/en_US/junos13.1/topics/concept/interfaces-interface-naming-overview.html">Juniper</a>,
%% <a href="http://www.openbsd.org/faq/faq6.html#Setup.if">BSD</a>,
%% <a href="https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/ArchitectOverview/ArchitectOverview.html#//apple_ref/doc/uid/TP0000013-BEHEGHEG">OSX</a>
%% (based on the BSD scheme),
%% etc. (and "anything goes" Windows) styles are equally valid. Consult your system
%% docs and/or query your own system with inet:getifaddrs/0 to discover valid schemes
%% and existing devices.

get_hw_addr(Name) ->
    case inet:getifaddrs() of
        {ok, []}         -> {error, no_iface};
        {ok, Interfaces} -> scan_hw_addr(Name, Interfaces);
        Error            -> Error
    end.


scan_hw_addr(_, []) ->
    {error, no_iface};
scan_hw_addr(Name, [{Name, Info} | _]) ->
    case lists:keyfind(hwaddr, 1, Info) of
        {hwaddr, [0,0,0,0,0,0]} -> {error, no_address};
        {hwaddr, MAC}           -> {ok, list_to_binary(MAC)};
        false                   -> {error, no_address}
    end;
scan_hw_addr(Name, [_ | T]) ->
    scan_hw_addr(Name, T).


-spec random_mac() -> ieee802mac().
%% @doc
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


-spec random_clock() -> clock_seq().
%% @doc
%% Generate a random 14-bit clock sequence.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_clock() ->
    <<_:2, ClockSeq:14>> = crypto:strong_rand_bytes(2),
    ClockSeq.


-spec random_uid() -> posix_id().
%% @doc
%% Generate a random 4-byte value for use as POSIX UID in version 2 UUID generation.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_uid() ->
    <<ID:32>> = crypto:strong_rand_bytes(4),
    ID.


-spec random_lid() -> local_id().
%% @doc
%% Generate a random 8-bit value for use as POSIX Group/Local ID value for use
%% in version 2 UUID generation.
%%
%% This function will always be called automatically when zuuid:start/0
%% is called the first time.

random_lid() ->
    <<ID:8>> = crypto:strong_rand_bytes(1),
    ID.


%% Manipulations

-spec strhexs_to_uuid([strhex()]) -> uuid().

strhexs_to_uuid(List) ->
    Bin = case strhexs_to_integers(List) of
        [A, B, C, D, E] -> <<A:32, B:16, C:16, D:16, E:48>>;
        [Value]         -> <<Value:128>>
    end,
    {uuid, Bin}.


-spec strhexs_to_mac([strhex()]) -> ieee802mac().

strhexs_to_mac(List) ->
    case strhexs_to_integers(List) of
        [A, B, C, D, E, F] -> <<A:8, B:8, C:8, D:8, E:8, F:8>>;
        [Value]            -> <<Value:48>>
    end.


-spec strhexs_to_integers([strhex()]) -> [integer()].

strhexs_to_integers(List) ->
    [list_to_integer(X, 16) || X <- List].


-spec bins_to_strhexs([{Bin, Size}]) -> StrHexs
    when Bin     :: binary(),
         Size    :: 4 | 8 | 12,
         StrHexs :: [strhex()].

bins_to_strhexs(List) ->
    [binary_to_strhex(X) || X <- List].


-spec binary_to_strhex({Bin, Size}) -> StrHex
    when Bin    :: binary(),
         Size   :: 4 | 8 | 12,
         StrHex :: strhex().

binary_to_strhex({Bin, Size}) ->
    string:right(integer_to_list(binary:decode_unsigned(Bin, big), 16), Size, $0).
