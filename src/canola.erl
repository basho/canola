%% Copyright (c) 2013 Basho Technologies, Inc.  All Rights Reserved.
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

-module(canola).

-export([open/0, open_debug/0, auth/4, close/1]).

%% API
open() ->
    open2(false).

open_debug() ->
    open2(true).

auth(Username, Password, Service, Port) when is_binary(Username), is_binary(Password),
                                             is_binary(Service), is_port(Port) ->
    port_command(Port, term_to_binary({Username, Password, Service})),
    receive
        {Port, {data, "+OK"}} ->
            ok;
        {Port, {data, "-ERR"}} ->
            error;
        {Port, {exit_status, _}} ->
            erlang:error(badarg)
    end;
auth(_, _, _, _) ->
    erlang:error(badarg).

close(Port) ->
    port_close(Port).

%% Internal functions

open2(Debug) ->
    Args = case Debug of
               true ->
                   ["-d"];
               _ ->
                   []
           end,
    PortBin = case code:priv_dir(ebloom) of
                 {error, bad_name} ->
                     case code:which(?MODULE) of
                         Filename when is_list(Filename) ->
                             filename:join([filename:dirname(Filename),"../priv", "canola-port"]);
                         _ ->
                             filename:join("priv", "canola-port")
                     end;
                 Dir ->
                     filename:join(Dir, "canpola-port")
             end,
    open_port({spawn_executable, PortBin}, [{args, Args}, {packet, 4}, exit_status]).
