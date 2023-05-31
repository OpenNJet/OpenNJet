all: lexer


lexer: njt_http_if_location_parse.c njt_http_if_location_lex.c njt_http_if_location_api.c
#       $(CC)  -Wall -W -Os -g -o  cli cli_demo.o -L. -lcli_int -ldl
	$(CC) -Og -ggdb -fsanitize=address -fno-omit-frame-pointer -Wno-comment -Wno-unused-function -static-libgcc -static-libasan -Wall -W -Os -g -o lexer njt_http_if_location_parse.c njt_http_if_location_lex.c njt_http_if_location_api.c

njt_http_if_location_parse.h njt_http_if_location_parse.c: loc_parse.y
	bison -d -o njt_http_if_location_parse.c loc_parse.y

njt_http_if_location_lex.h njt_http_if_location_lex.c:loc_lex.l
	flex -d --header-file=njt_http_if_location_lex.h  -o njt_http_if_location_lex.c loc_lex.l

njt_http_if_location_api.h njt_http_if_location_api.c:

clean:
	rm -f lexer ./*.o  njt_http_if_location_parse.h njt_http_if_location_parse.c njt_http_if_location_lex.h njt_http_if_location_lex.c
