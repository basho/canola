%% -------------------------------------------------------------------
%%
%% Copyright (c) 2013-2017 Basho Technologies, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

%%
%% @doc Erlang Wrapper for Pluggable Authentication Modules (PAM).
%%
%% @reference X/Open Single Sign-On Service (XSSO) - Pluggable Authentication Modules<br />
%%  [http://pubs.opengroup.org/onlinepubs/8329799/]
%%
-module(canola).

-export([auth/3]).

-ifdef(BASHO_CHECK).
%% Dialyzer and XRef won't recognize 'on_load' as using the function and
%% will complain about it.
-export([init_nif_lib/0]).
-endif.
-on_load(init_nif_lib/0).

-define(APPLICATION, canola).

%% ===================================================================
%% Public API
%% ===================================================================

%%
%% @doc Attempt to authenticate the specified User for the specified Service.
%%
%% If the User is authenticated successfully `ok' is returned.
%%
%% On failure, errors are classified as `auth' or `system'.
%% Generally, if the first element of the error Reason is `auth', the call
%% was successful but the credentials are not valid, and if the fist element
%% is `system' an error occurred processing the request. In the latter case,
%% it's likely that PAM is not properly configured on the system.
%%
%% The third element of an `error' Reason tuple identifies the location within
%% the implementation code where the failure was identified, and is of limited
%% value to users.
%%
-spec auth(Service :: binary(), User :: binary(), Password :: binary())
            -> ok | {error, {auth | system, Reason :: string(), Loc :: pos_integer()}}.

auth(_Service, _Username, _Password) ->
    erlang:nif_error(nif_not_loaded).

%% ===================================================================
%% NIF initialization
%% ===================================================================

init_nif_lib() ->
    SoDir = case code:priv_dir(?APPLICATION) of
        {error, bad_name} ->
            ADir =  case code:which(?MODULE) of
                Beam when is_list(Beam) ->
                    filename:dirname(filename:dirname(Beam));
                _ ->
                    {ok, CWD} = file:get_cwd(),
                    % This is almost certainly wrong, but it'll end
                    % up equivalent to "../priv".
                    filename:dirname(CWD)
            end,
            filename:join(ADir, "priv");
        PDir ->
            PDir
    end,
    % AppEnv = [{debug, {file, "/tmp/canola.log"}}],
    AppEnv = application:get_all_env(?APPLICATION),
    erlang:load_nif(filename:join(SoDir, ?APPLICATION), AppEnv).
