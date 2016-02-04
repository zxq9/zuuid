%%% @doc
%%% zUUID supervisor process.
%%%
%%% The supervisor process for the zUUID application. This module only defines
%%% a bare-minimum supervisor over the UUID state manager. The state manager is
%%% intended to only be run once per node, and only applies to generation of
%%% version 1 and 2 UUIDs (time-based generators).
%%%
%%% In special cases where multiple zUUID version 1 or 2 generators are desired
%%% on a single node, adjusting this module to behave as a simple_one_for_one
%%% or to have multiple permanent children registered differently would be
%%% a simple change and not interfere with the way the modules work (each
%%% state manager is configurable after startup with {@link zuuid:config/1}).
%%%
%%% @see zuuid:config/1.
%%% @see zuuid:start/0.
%%% @end

-module(zuuid_sup).
-author("Craig Everett <zxq9@zxq9.com>").
-behavior(supervisor).

-export([start_link/1]).
-export([init/1]).

-pure([init/1]).

-spec start_link(Args) -> Result
    when Args   :: term(),
         Result :: {ok, pid()}
                 | {error, Reason},
         Reason :: {already_started, pid()}
                 | {shutdown, term()}
                 | term().
%% @private
%% Called by zuuid:start/0.
%%
%% Error conditions are explained in the supervisor module docs:
%% http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/supervisor.html#start_link-3

start_link(_) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, none).


-spec init(none) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
%% @doc
%% @private
%% Do not call this function directly -- it is exported only because it is a
%% necessary part of the OTP
%% <a href="http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/supervisor.html">supervisor</a>
%% behavior.
%%
%% As mentioned in the docs for R18,
%% <a href="http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/supervisor.html#type-sup_flags">supervisor flags</a>
%% and
%% <a href="http://zxq9.com/erlang/docs/reg/18.0/lib/stdlib-2.5/doc/html/supervisor.html#type-child_spec">child specs</a>
%% can be defined as tupled or maps, with maps being officially recommended but being
%% supported only by R18 and later. At the time of zuuid's release (February 2016) that
%% prevents zuuid from being used by most deployed Erlang environments. They have
%% therefore been defined as tuples below, but equivalent definitions as maps would be:
%% ```
%% RestartStrategy = #{strategy  => one_for_one,
%%                     intensity => 1,
%%                     period    => 60},
%% '''
%% ```
%% UUID_Man = #{id    => zuuid_man,
%%              start => {zuuid_man, start_link, []},
%%              type  => worker},
%% '''
%% The important part about these definitions is to recognize that zuuid_man is the
%% worker process that manages the state of the UUID v1 and v2 generators and performs
%% some (very basic) checks to ensure duplicate values are not accidentally generated
%% in the case calls to {@link zuuid:v1/0} or {@link zuuid:v2/0} occur faster than
%% 100 nanosecond intervals (or, really, that a series of return values are not closer
%% than that). This worker (and therefore its state) should be permanent for the life
%% of the node unless explicitly turned off (via {@link zuuid:stop/0}), and since it
%% acquired no external resources and maintains no persistent state on its own there
%% is no benefit in not brutally killing on termination if it exits abnormally or hangs
%% for some reason on shutdown.

init(none) ->
    RestartStrategy =
        {one_for_one,                   % A "normal" supervisor.
         1,                             % Give workers 1 chance to restart within any
         60},                           % 60 second period.
    UUID_Man =
        {zuuid_man,                     % Internal name for this child process.
         {zuuid_man, start_link, []},   % Start execution at {Module, Function, Args}.
         permanent,                     % Should exist for the life of the node.
         brutal_kill,                   % No resources to free or state to store.
         worker,                        % A worker that represents useful state.
         [zuuid_man]},                  % Module indicator for release handler.
    {ok, {RestartStrategy, [UUID_Man]}}.
