/* A Bison parser, made by GNU Bison 1.875.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TOKJUNK = 258,
     TOKSUBNET = 259,
     TOKDEV = 260,
     TOKSLASH = 261,
     TOKSKIPINTERVALS = 262,
     TOKGRAPHCUTOFF = 263,
     TOKPROMISC = 264,
     TOKOUTPUTCDF = 265,
     TOKRECOVERCDF = 266,
     TOKGRAPH = 267,
     TOKNEWLINE = 268,
     TOKFILTER = 269,
     TOKMETAREFRESH = 270,
     TOKPGSQLCONNECTSTRING = 271,
     TOKSENSORID = 272,
     IPADDR = 273,
     NUMBER = 274,
     STRING = 275,
     STATE = 276
   };
#endif
#define TOKJUNK 258
#define TOKSUBNET 259
#define TOKDEV 260
#define TOKSLASH 261
#define TOKSKIPINTERVALS 262
#define TOKGRAPHCUTOFF 263
#define TOKPROMISC 264
#define TOKOUTPUTCDF 265
#define TOKRECOVERCDF 266
#define TOKGRAPH 267
#define TOKNEWLINE 268
#define TOKFILTER 269
#define TOKMETAREFRESH 270
#define TOKPGSQLCONNECTSTRING 271
#define TOKSENSORID 272
#define IPADDR 273
#define NUMBER 274
#define STRING 275
#define STATE 276




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 38 "conf.y"
typedef union YYSTYPE {
    int number;
    char *string;
} YYSTYPE;
/* Line 1248 of yacc.c.  */
#line 83 "y.tab.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE bdconfig_lval;



