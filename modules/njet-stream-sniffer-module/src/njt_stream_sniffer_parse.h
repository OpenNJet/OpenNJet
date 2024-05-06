/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_SNIFFER_NJT_STREAM_SNIFFER_PARSE_H_INCLUDED
# define YY_SNIFFER_NJT_STREAM_SNIFFER_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef SNIFFERDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define SNIFFERDEBUG 1
#  else
#   define SNIFFERDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define SNIFFERDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined SNIFFERDEBUG */
#if SNIFFERDEBUG
extern int snifferdebug;
#endif

/* Token kinds.  */
#ifndef SNIFFERTOKENTYPE
# define SNIFFERTOKENTYPE
  enum sniffertokentype
  {
    SNIFFEREMPTY = -2,
    SNIFFEREOF = 0,                /* "end of file"  */
    SNIFFERerror = 256,            /* error  */
    SNIFFERUNDEF = 257,            /* "invalid token"  */
    LOC_EXP = 258,                 /* LOC_EXP  */
    OR = 259,                      /* OR  */
    AND = 260,                     /* AND  */
    ERROR = 261                    /* ERROR  */
  };
  typedef enum sniffertokentype sniffertoken_kind_t;
#endif

/* Value type.  */
#if ! defined SNIFFERSTYPE && ! defined SNIFFERSTYPE_IS_DECLARED
union SNIFFERSTYPE
{
#line 11 "sniffer_parse.y"

  sniffer_exp_parse_node_t *node;
  sniffer_exp_t *loc_exp;

#line 83 "njt_stream_sniffer_parse.h"

};
typedef union SNIFFERSTYPE SNIFFERSTYPE;
# define SNIFFERSTYPE_IS_TRIVIAL 1
# define SNIFFERSTYPE_IS_DECLARED 1
#endif


extern SNIFFERSTYPE snifferlval;


int snifferparse (sniffer_exp_parse_node_t **tree_root);


#endif /* !YY_SNIFFER_NJT_STREAM_SNIFFER_PARSE_H_INCLUDED  */
