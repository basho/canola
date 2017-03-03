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

%%
%% If there's a known account in PAM on your local system for testing,
%% define this to the service, username, and password for a live test.
%% DO NOT commit a dependency on your local configuration!
%%
% -define(TEST_LOCAL_USER, {<<"cups">>, <<"guest">>, <<"">>}).

auth_test_() ->
    {timeout, 30, fun() ->
        BogusPW = <<"ReallyHopeThisIsntYourPassword">>,
        FakeSvc = <<"ThereShouldntBeAServiceWithThisName">>,
        RealSvc = <<"login">>,
        FakeUsr = <<"NoSuchUserWeHope">>,
        UsrName = case os:getenv("USER") of
            false ->
                os:getenv("LOGNAME");
            Name ->
                Name
        end,
        ?assert(erlang:is_list(UsrName)),
        RealUsr = erlang:list_to_binary(UsrName),

        Ret1 = canola:auth(RealSvc, RealUsr, BogusPW),
        % ?debugVal(Ret1),
        ?assertMatch({error, {auth, _, _}}, Ret1),

        Ret2 = canola:auth(FakeSvc, RealUsr, BogusPW),
        % ?debugVal(Ret2),
        ?assertMatch({error, {auth, _, _}}, Ret2),

        Ret3 = canola:auth(RealSvc, <<"root">>, <<"password">>),
        % ?debugVal(Ret3),
        ?assertMatch({error, {auth, _, _}}, Ret3),

        Ret4 = canola:auth(RealSvc, FakeUsr, BogusPW),
        % ?debugVal(Ret4),
        ?assertMatch({error, {auth, _, _}}, Ret4),

        ?assertError(badarg, canola:auth(RealSvc, UsrName, BogusPW))
    end}.

-ifdef(TEST_LOCAL_USER).

user_test() ->
    {Service, Username, Password} = ?TEST_LOCAL_USER,
    ?assertEqual(ok, canola:auth(Service, Username, Password)).

-endif. % TEST_USER_NAME_PASS
