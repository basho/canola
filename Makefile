.PHONY: all compile clean

all: compile

compile:
	./rebar compile

clean:
	./rebar clean

DIALYZER_APPS = kernel stdlib erts sasl eunit syntax_tools compiler crypto

include tools.mk
