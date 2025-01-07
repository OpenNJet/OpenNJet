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

#ifndef YY_NJT_EXP_NJT_HTTP_IF_LOCATION_PARSE_H_INCLUDED
# define YY_NJT_EXP_NJT_HTTP_IF_LOCATION_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef NJT_EXPDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define NJT_EXPDEBUG 1
#  else
#   define NJT_EXPDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define NJT_EXPDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined NJT_EXPDEBUG */
#if NJT_EXPDEBUG
extern int njt_expdebug;
#endif

/* Token kinds.  */
#ifndef NJT_EXPTOKENTYPE
# define NJT_EXPTOKENTYPE
  enum njt_exptokentype
  {
    NJT_EXPEMPTY = -2,
    NJT_EXPEOF = 0,                /* "end of file"  */
    NJT_EXPerror = 256,            /* error  */
    NJT_EXPUNDEF = 257,            /* "invalid token"  */
    LOC_EXP = 258,                 /* LOC_EXP  */
    OR = 259,                      /* OR  */
    AND = 260,                     /* AND  */
    ERROR = 261                    /* ERROR  */
  };
  typedef enum njt_exptokentype njt_exptoken_kind_t;
#endif

/* Value type.  */
#if ! defined NJT_EXPSTYPE && ! defined NJT_EXPSTYPE_IS_DECLARED
union NJT_EXPSTYPE
{
#line 14 "loc_parse.y"

  loc_parse_node_t *node;
  loc_exp_t *loc_exp;

#line 83 "njt_http_if_location_parse.h"

};
typedef union NJT_EXPSTYPE NJT_EXPSTYPE;
# define NJT_EXPSTYPE_IS_TRIVIAL 1
# define NJT_EXPSTYPE_IS_DECLARED 1
#endif


extern NJT_EXPSTYPE njt_explval;


int njt_expparse (loc_parse_node_t **tree_root);


#endif /* !YY_NJT_EXP_NJT_HTTP_IF_LOCATION_PARSE_H_INCLUDED  */
