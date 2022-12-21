%% -------------------------------------------------------------------
%%
%% Copyright (c) 2017 Basho Technologies, Inc.
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

-module(canola_tests).

-include_lib("eunit/include/eunit.hrl").


-ifdef(GITHUBEXCLUDE).

user_test() ->
    P = canola:open_debug(),
    canola:close(P).

-else.

auth_test_() ->
    {timeout, 30, fun() ->
        BogusPW = <<"ReallyHopeThisIsntYourPassword">>,
        FakeSvc = <<"ThereShouldntBeAServiceWithThisName">>,
        RealSvc = <<"login">>,
        FakeUsr = <<"NoSuchUserWeHope">>,
        UsrName = 
            case os:getenv("USER") of
                false ->
                    os:getenv("LOGNAME");
                Name ->
                    Name
            end,
        P = canola:open_debug(),
        ?assert(erlang:is_list(UsrName)),
        RealUsr = erlang:list_to_binary(UsrName),

        Ret1 = canola:auth(RealSvc, RealUsr, BogusPW, P),
        % ?debugVal(Ret1),
        ?assertEqual(error, Ret1),

        Ret2 = canola:auth(FakeSvc, RealUsr, BogusPW, P),
        % ?debugVal(Ret2),
        ?assertEqual(error, Ret2),

        Ret3 = canola:auth(RealSvc, <<"root">>, <<"password">>, P),
        % ?debugVal(Ret3),
        ?assertEqual(error, Ret3),

        Ret4 = canola:auth(RealSvc, FakeUsr, BogusPW, P),
        % ?debugVal(Ret4),
        ?assertEqual(error, Ret4),

        ?assertError(badarg, canola:auth(RealSvc, UsrName, BogusPW, P)),
        canola:close(P)
    end}.

-endif.