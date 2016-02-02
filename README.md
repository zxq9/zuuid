# zuuid
An example Erlang project that implements RFC 4122 UUID generators and functions.

## What it is
An RFC 4122 UUID implementation in Erlang focused on readability, plain coding style
and clear documentation.

This is a fully-featured UUID generation utility, despite being an example project.
This project implements version 1, 2, 3, 4 and 5 UUIDs, and includes a process-based
implementation of a value-checker to guarantee that high-frequency calls to version
1 and 2 generators will not result in accidentally duplicate values.

## Links

### Documentation
http://zxq9.com/projects/zuuid/docs/

### Source
https://github.com/zxq9/zuuid

## An Example Shell Session

    1> zuuid:start().
    ok
    2> {ok, MAC} = zuuid:get_hw_addr("eth0").
    {ok,<<184,107,35,128,22,24>>}
    3> zuuid:config({node, MAC}).
    ok
    4> UUID = zuuid:v1().
    {uuid,<<156,80,133,236,201,174,17,229,154,56,184,107,35,128,22,24>>}
    5> zuuid:version(UUID).
    {rfc4122,1}
    6> zuuid:string(UUID).
    "{9C5085EC-C9AE-11E5-9A38-B86B23801618}"
    7> zuuid:binary(zuuid:v4()).
    <<"{A2AF6D62-0D40-446E-BF89-108082A4E809}">>
    8> U2 = zuuid:read_uuid("12345678-90ab-cdef-1234-567890abcdef").
    {uuid,<<18,52,86,120,144,171,205,239,18,52,86,120,144,171,205,239>>}
    9> zuuid:version(U2).
    {ncs,compatibility}
    10> zuuid:string(U2).
    "{12345678-90AB-CDEF-1234-567890ABCDEF}"
    11> NewMAC = zuuid:read_mac("12:34:56:78:90:ab").
    <<18,52,86,120,144,171>>
    12> zuuid:config({node, NewMAC}).
    ok
    13> zuuid:string(zuuid:v1()).
    "{86BAD2C8-C9AF-11E5-9A38-1234567890AB}"

## Contributing
Anything missing? Silly? Stupid? Buggy? Want to actually use it in a real project (and
so really want some erlang.mk or rebar3 files added)? Send a pull request, file a bug,
or just send me an email.
