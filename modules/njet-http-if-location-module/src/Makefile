all: lexer


lexer: lex.yy.c loc_parse.tab.c loc_eval.c
#       $(CC)  -Wall -W -Os -g -o  cli cli_demo.o -L. -lcli_int -ldl
	$(CC) -ggdb -fsanitize=address -fno-omit-frame-pointer -Wno-comment -Wno-unused-function -static-libgcc -static-libasan -Wall -W -Os -g -o  lexer lex.yy.c loc_parse.tab.c loc_eval.c

loc_parse.tab.h loc_parse.tab.c: loc_parse.y
	bison -d loc_parse.y

lex.yy.h lex.yy.c:loc_lex.l
	flex --header-file=lex.yy.h loc_lex.l

loc_eval.c:

clean:
	rm -f lexer ./*.o  lex.yy.c lex.yy.h loc_parse.tab.c loc_parse.tab.h
