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
%%% state manager is configurable after startup with zuuid:config/1).
%%%
%%% @see zuuid:config/1.
%%% @see zuuid:start/0.
%%% @end

-module(zuuid_sup).
-behavior(supervisor).
-export([start_link/1]).
-export([init/1]).

-pure([init/1]).

%% @private
-spec start_link(Args) -> Result
    when Args   :: term(),
         Result :: {ok, pid()}
                 | {error, Reason},
         Reason :: {already_started, pid()}
                 | {shutdown, term()}
                 | term().
start_link(_) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, none).

%% @private
-spec init(none) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(none) ->
    RestartStrategy = #{strategy  => one_for_one,
                        intensity => 1,
                        period    => 60},
    UUID_Man = #{id    => zuuid_man,
                 start => {zuuid_man, start_link, []},
                 type  => worker},
    {ok, {RestartStrategy, [UUID_Man]}}.
