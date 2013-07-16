Canola
======

Canola, a PAM port driver for the GPL intolerant.

Usage
=====

```erlang
1> P = canola:open().
#Port<0.741>
2> canola:auth(<<"andrew">>, <<"password">>, <<"service">>, P).
ok
3> canola:auth(<<"andrew">>, <<"badpassword">>, <<"service">>, P).
error
4> canola:close(P).
true
5>
```
