all: lexer


lexer: njt_stream_sniffer_parse.c njt_stream_sniffer_lex.c njt_stream_sniffer_module.c
#       $(CC)  -Wall -W -Os -g -o  cli cli_demo.o -L. -lcli_int -ldl
	#$(CC) -Og -ggdb -fsanitize=address -fno-omit-frame-pointer -Wno-comment -Wno-unused-function -static-libgcc -static-libasan -Wall -W -Os -g -o lexer njt_stream_sniffer_parse.c njt_stream_sniffer_lex.c njt_stream_sniffer_module.c

njt_stream_sniffer_parse.h njt_stream_sniffer_parse.c: sniffer_parse.y
	bison -d -Dapi.prefix=sniffer  -o njt_stream_sniffer_parse.c sniffer_parse.y

njt_stream_sniffer_lex.h njt_stream_sniffer_lex.c:sniffer_lex.l
	#flex -d --header-file=njt_stream_sniffer_lex.h  -o njt_stream_sniffer_lex.c loc_lex.l
	flex -d  --prefix=sniffer  --header-file=njt_stream_sniffer_lex.h  -o njt_stream_sniffer_lex.c sniffer_lex.l

njt_stream_sniffer.h njt_stream_sniffer_module.c:

clean:
	rm -f lexer ./*.o  njt_stream_sniffer_parse.*  njt_stream_sniffer_lex.*
