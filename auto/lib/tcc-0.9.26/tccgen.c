/*
 *  TCC - Tiny C Compiler
 * 
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

/********************************************************/
/* global variables */

/* loc : local variable index
   ind : output code index
   rsym: return symbol
   anon_sym: anonymous symbol index
*/
ST_DATA int rsym, anon_sym, ind, loc;

ST_DATA Section *text_section, *data_section, *bss_section; /* predefined sections */
ST_DATA Section *cur_text_section; /* current section where function code is generated */
#ifdef CONFIG_TCC_ASM
ST_DATA Section *last_text_section; /* to handle .previous asm directive */
#endif
#ifdef CONFIG_TCC_BCHECK
/* bound check related sections */
ST_DATA Section *bounds_section; /* contains global data bound description */
ST_DATA Section *lbounds_section; /* contains local data bound description */
#endif
/* symbol sections */
ST_DATA Section *symtab_section, *strtab_section;
/* debug sections */
ST_DATA Section *stab_section, *stabstr_section;
ST_DATA Sym *sym_free_first;
ST_DATA void **sym_pools;
ST_DATA int nb_sym_pools;

ST_DATA Sym *global_stack;
ST_DATA Sym *local_stack;
ST_DATA Sym *define_stack;
ST_DATA Sym *global_label_stack;
ST_DATA Sym *local_label_stack;
static int local_scope;

ST_DATA int vlas_in_scope; /* number of VLAs that are currently in scope */
ST_DATA int vla_sp_root_loc; /* vla_sp_loc for SP before any VLAs were pushed */
ST_DATA int vla_sp_loc; /* Pointer to variable holding location to store stack pointer on the stack when modifying stack pointer */

ST_DATA SValue __vstack[1+VSTACK_SIZE], *vtop, *pvtop;

ST_DATA int const_wanted; /* true if constant wanted */
ST_DATA int nocode_wanted; /* true if no code generation wanted for an expression */
ST_DATA int global_expr;  /* true if compound literals must be allocated globally (used during initializers parsing */
ST_DATA CType func_vt; /* current function return type (used by return instruction) */
ST_DATA int func_var; /* true if current function is variadic (used by return instruction) */
ST_DATA int func_vc;
ST_DATA int last_line_num, last_ind, func_ind; /* debug last line number and pc */
ST_DATA const char *funcname;

ST_DATA CType char_pointer_type, func_old_type, int_type, size_type;

/* ------------------------------------------------------------------------- */
static void gen_cast(CType *type);
static inline CType *pointed_type(CType *type);
static int is_compatible_types(CType *type1, CType *type2);
static int parse_btype(CType *type, AttributeDef *ad);
static void type_decl(CType *type, AttributeDef *ad, int *v, int td);
static void parse_expr_type(CType *type);
static void decl_initializer(CType *type, Section *sec, unsigned long c, int first, int size_only);
static void block(int *bsym, int *csym, int *case_sym, int *def_sym, int case_reg, int is_expr);
static void decl_initializer_alloc(CType *type, AttributeDef *ad, int r, int has_init, int v, int scope);
static int decl0(int l, int is_for_loop_init);
static void expr_eq(void);
static void expr_lor_const(void);
static void unary_type(CType *type);
static void vla_runtime_type_size(CType *type, int *a);
static void vla_sp_restore(void);
static void vla_sp_restore_root(void);
static int is_compatible_parameter_types(CType *type1, CType *type2);
static void expr_type(CType *type);
ST_FUNC void vpush64(int ty, unsigned long long v);
ST_FUNC void vpush(CType *type);
ST_FUNC int gvtst(int inv, int t);
ST_FUNC int is_btype_size(int bt);

ST_INLN int is_float(int t)
{
    int bt;
    bt = t & VT_BTYPE;
    return bt == VT_LDOUBLE || bt == VT_DOUBLE || bt == VT_FLOAT || bt == VT_QFLOAT;
}

/* we use our own 'finite' function to avoid potential problems with
   non standard math libs */
/* XXX: endianness dependent */
ST_FUNC int ieee_finite(double d)
{
    int p[4];
    memcpy(p, &d, sizeof(double));
    return ((unsigned)((p[1] | 0x800fffff) + 1)) >> 31;
}

ST_FUNC void test_lvalue(void)
{
    if (!(vtop->r & VT_LVAL))
        expect("lvalue");
}

ST_FUNC void check_vstack(void)
{
    if (pvtop != vtop)
        tcc_error("internal compiler error: vstack leak (%d)", vtop - pvtop);
}

/* ------------------------------------------------------------------------- */
/* symbol allocator */
static Sym *__sym_malloc(void)
{
    Sym *sym_pool, *sym, *last_sym;
    int i;

    sym_pool = tcc_malloc(SYM_POOL_NB * sizeof(Sym));
    dynarray_add(&sym_pools, &nb_sym_pools, sym_pool);

    last_sym = sym_free_first;
    sym = sym_pool;
    for(i = 0; i < SYM_POOL_NB; i++) {
        sym->next = last_sym;
        last_sym = sym;
        sym++;
    }
    sym_free_first = last_sym;
    return last_sym;
}

static inline Sym *sym_malloc(void)
{
    Sym *sym;
    sym = sym_free_first;
    if (!sym)
        sym = __sym_malloc();
    sym_free_first = sym->next;
    return sym;
}

ST_INLN void sym_free(Sym *sym)
{
    sym->next = sym_free_first;
    sym_free_first = sym;
}

/* push, without hashing */
ST_FUNC Sym *sym_push2(Sym **ps, int v, int t, long c)
{
    Sym *s;

    s = sym_malloc();
    s->asm_label = 0;
    s->v = v;
    s->type.t = t;
    s->type.ref = NULL;
#ifdef _WIN64
    s->d = NULL;
#endif
    s->c = c;
    s->next = NULL;
    /* add in stack */
    s->prev = *ps;
    *ps = s;
    return s;
}

/* find a symbol and return its associated structure. 's' is the top
   of the symbol stack */
ST_FUNC Sym *sym_find2(Sym *s, int v)
{
    while (s) {
        if (s->v == v)
            return s;
        else if (s->v == -1)
            return NULL;
        s = s->prev;
    }
    return NULL;
}

/* structure lookup */
ST_INLN Sym *struct_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_struct;
}

/* find an identifier */
ST_INLN Sym *sym_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_identifier;
}

/* push a given symbol on the symbol stack */
ST_FUNC Sym *sym_push(int v, CType *type, int r, int c)
{
    Sym *s, **ps;
    TokenSym *ts;

    if (local_stack)
        ps = &local_stack;
    else
        ps = &global_stack;
    s = sym_push2(ps, v, type->t, c);
    s->type.ref = type->ref;
    s->r = r;
    /* don't record fields or anonymous symbols */
    /* XXX: simplify */
    if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
        /* record symbol in token array */
        ts = table_ident[(v & ~SYM_STRUCT) - TOK_IDENT];
        if (v & SYM_STRUCT)
            ps = &ts->sym_struct;
        else
            ps = &ts->sym_identifier;
        s->prev_tok = *ps;
        *ps = s;
        s->scope = local_scope;
        if (s->prev_tok && s->prev_tok->scope == s->scope)
            tcc_error("redeclaration of '%s'",
                get_tok_str(v & ~SYM_STRUCT, NULL));
    }
    return s;
}

/* push a global identifier */
ST_FUNC Sym *global_identifier_push(int v, int t, int c)
{
    Sym *s, **ps;
    s = sym_push2(&global_stack, v, t, c);
    /* don't record anonymous symbol */
    if (v < SYM_FIRST_ANOM) {
        ps = &table_ident[v - TOK_IDENT]->sym_identifier;
        /* modify the top most local identifier, so that
           sym_identifier will point to 's' when popped */
        while (*ps != NULL)
            ps = &(*ps)->prev_tok;
        s->prev_tok = NULL;
        *ps = s;
    }
    return s;
}

/* pop symbols until top reaches 'b' */
ST_FUNC void sym_pop(Sym **ptop, Sym *b)
{
    Sym *s, *ss, **ps;
    TokenSym *ts;
    int v;

    s = *ptop;
    while(s != b) {
        ss = s->prev;
        v = s->v;
        /* remove symbol in token array */
        /* XXX: simplify */
        if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
            ts = table_ident[(v & ~SYM_STRUCT) - TOK_IDENT];
            if (v & SYM_STRUCT)
                ps = &ts->sym_struct;
            else
                ps = &ts->sym_identifier;
            *ps = s->prev_tok;
        }
        sym_free(s);
        s = ss;
    }
    *ptop = b;
}

static void weaken_symbol(Sym *sym)
{
    sym->type.t |= VT_WEAK;
    if (sym->c > 0) {
        int esym_type;
        ElfW(Sym) *esym;
        
        esym = &((ElfW(Sym) *)symtab_section->data)[sym->c];
        esym_type = ELFW(ST_TYPE)(esym->st_info);
        esym->st_info = ELFW(ST_INFO)(STB_WEAK, esym_type);
    }
}

static void apply_visibility(Sym *sym, CType *type)
{
    int vis = sym->type.t & VT_VIS_MASK;
    int vis2 = type->t & VT_VIS_MASK;
    if (vis == (STV_DEFAULT << VT_VIS_SHIFT))
        vis = vis2;
    else if (vis2 == (STV_DEFAULT << VT_VIS_SHIFT))
        ;
    else
        vis = (vis < vis2) ? vis : vis2;
    sym->type.t &= ~VT_VIS_MASK;
    sym->type.t |= vis;

    if (sym->c > 0) {
        ElfW(Sym) *esym;
        
        esym = &((ElfW(Sym) *)symtab_section->data)[sym->c];
	vis >>= VT_VIS_SHIFT;
        esym->st_other = (esym->st_other & ~ELFW(ST_VISIBILITY)(-1)) | vis;
    }
}

/* ------------------------------------------------------------------------- */

ST_FUNC void swap(int *p, int *q)
{
    int t;
    t = *p;
    *p = *q;
    *q = t;
}

static void vsetc(CType *type, int r, CValue *vc)
{
    int v;

    if (vtop >= vstack + (VSTACK_SIZE - 1))
        tcc_error("memory full (vstack)");
    /* cannot let cpu flags if other instruction are generated. Also
       avoid leaving VT_JMP anywhere except on the top of the stack
       because it would complicate the code generator. */
    if (vtop >= vstack) {
        v = vtop->r & VT_VALMASK;
        if (v == VT_CMP || (v & ~1) == VT_JMP)
            gv(RC_INT);
    }
    vtop++;
    vtop->type = *type;
    vtop->r = r;
    vtop->r2 = VT_CONST;
    vtop->c = *vc;
}

/* push constant of type "type" with useless value */
ST_FUNC void vpush(CType *type)
{
    CValue cval;
    vsetc(type, VT_CONST, &cval);
}

/* push integer constant */
ST_FUNC void vpushi(int v)
{
    CValue cval;
    cval.i = v;
    vsetc(&int_type, VT_CONST, &cval);
}

/* push a pointer sized constant */
static void vpushs(addr_t v)
{
  CValue cval;
  cval.i = v;
  vsetc(&size_type, VT_CONST, &cval);
}

/* push arbitrary 64bit constant */
ST_FUNC void vpush64(int ty, unsigned long long v)
{
    CValue cval;
    CType ctype;
    ctype.t = ty;
    ctype.ref = NULL;
    cval.i = v;
    vsetc(&ctype, VT_CONST, &cval);
}

/* push long long constant */
static inline void vpushll(long long v)
{
    vpush64(VT_LLONG, v);
}

/* push a symbol value of TYPE */
static inline void vpushsym(CType *type, Sym *sym)
{
    CValue cval;
    cval.i = 0;
    vsetc(type, VT_CONST | VT_SYM, &cval);
    vtop->sym = sym;
}

/* Return a static symbol pointing to a section */
ST_FUNC Sym *get_sym_ref(CType *type, Section *sec, unsigned long offset, unsigned long size)
{
    int v;
    Sym *sym;

    v = anon_sym++;
    sym = global_identifier_push(v, type->t | VT_STATIC, 0);
    sym->type.ref = type->ref;
    sym->r = VT_CONST | VT_SYM;
    put_extern_sym(sym, sec, offset, size);
    return sym;
}

/* push a reference to a section offset by adding a dummy symbol */
static void vpush_ref(CType *type, Section *sec, unsigned long offset, unsigned long size)
{
    vpushsym(type, get_sym_ref(type, sec, offset, size));  
}

/* define a new external reference to a symbol 'v' of type 'u' */
ST_FUNC Sym *external_global_sym(int v, CType *type, int r)
{
    Sym *s;

    s = sym_find(v);
    if (!s) {
        /* push forward reference */
        s = global_identifier_push(v, type->t | VT_EXTERN, 0);
        s->type.ref = type->ref;
        s->r = r | VT_CONST | VT_SYM;
    }
    return s;
}

/* define a new external reference to a symbol 'v' */
static Sym *external_sym(int v, CType *type, int r)
{
    Sym *s;

    s = sym_find(v);
    if (!s) {
        /* push forward reference */
        s = sym_push(v, type, r | VT_CONST | VT_SYM, 0);
        s->type.t |= VT_EXTERN;
    } else if (s->type.ref == func_old_type.ref) {
        s->type.ref = type->ref;
        s->r = r | VT_CONST | VT_SYM;
        s->type.t |= VT_EXTERN;
    } else if (!is_compatible_types(&s->type, type)) {
        tcc_error("incompatible types for redefinition of '%s'", 
              get_tok_str(v, NULL));
    }
    /* Merge some storage attributes.  */
    if (type->t & VT_WEAK)
        weaken_symbol(s);

    if (type->t & VT_VIS_MASK)
        apply_visibility(s, type);

    return s;
}

/* push a reference to global symbol v */
ST_FUNC void vpush_global_sym(CType *type, int v)
{
    vpushsym(type, external_global_sym(v, type, 0));
}

ST_FUNC void vset(CType *type, int r, int v)
{
    CValue cval;

    cval.i = v;
    vsetc(type, r, &cval);
}

static void vseti(int r, int v)
{
    CType type;
    type.t = VT_INT;
    type.ref = 0;
    vset(&type, r, v);
}

ST_FUNC void vswap(void)
{
    SValue tmp;
    /* cannot let cpu flags if other instruction are generated. Also
       avoid leaving VT_JMP anywhere except on the top of the stack
       because it would complicate the code generator. */
    if (vtop >= vstack) {
        int v = vtop->r & VT_VALMASK;
        if (v == VT_CMP || (v & ~1) == VT_JMP)
            gv(RC_INT);
    }
    tmp = vtop[0];
    vtop[0] = vtop[-1];
    vtop[-1] = tmp;

/* XXX: +2% overall speed possible with optimized memswap
 *
 *  memswap(&vtop[0], &vtop[1], sizeof *vtop);
 */
}

ST_FUNC void vpushv(SValue *v)
{
    if (vtop >= vstack + (VSTACK_SIZE - 1))
        tcc_error("memory full (vstack)");
    vtop++;
    *vtop = *v;
}

static void vdup(void)
{
    vpushv(vtop);
}

/* save r to the memory stack, and mark it as being free */
ST_FUNC void save_reg(int r)
{
    int l, saved, size, align;
    SValue *p, sv;
    CType *type;

    /* modify all stack values */
    saved = 0;
    l = 0;
    for(p=vstack;p<=vtop;p++) {
        if ((p->r & VT_VALMASK) == r ||
            ((p->type.t & VT_BTYPE) == VT_LLONG && (p->r2 & VT_VALMASK) == r)) {
            /* must save value on stack if not already done */
            if (!saved) {
                /* NOTE: must reload 'r' because r might be equal to r2 */
                r = p->r & VT_VALMASK;
                /* store register in the stack */
                type = &p->type;
                if ((p->r & VT_LVAL) ||
                    (!is_float(type->t) && (type->t & VT_BTYPE) != VT_LLONG))
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                    type = &char_pointer_type;
#else
                    type = &int_type;
#endif
                size = type_size(type, &align);
                loc = (loc - size) & -align;
                sv.type.t = type->t;
                sv.r = VT_LOCAL | VT_LVAL;
                sv.c.i = loc;
                store(r, &sv);
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
                /* x86 specific: need to pop fp register ST0 if saved */
                if (r == TREG_ST0) {
                    o(0xd8dd); /* fstp %st(0) */
                }
#endif
#if !defined(TCC_TARGET_ARM64) && !defined(TCC_TARGET_X86_64)
                /* special long long case */
                if ((type->t & VT_BTYPE) == VT_LLONG) {
                    sv.c.i += 4;
                    store(p->r2, &sv);
                }
#endif
                l = loc;
                saved = 1;
            }
            /* mark that stack entry as being saved on the stack */
            if (p->r & VT_LVAL) {
                /* also clear the bounded flag because the
                   relocation address of the function was stored in
                   p->c.i */
                p->r = (p->r & ~(VT_VALMASK | VT_BOUNDED)) | VT_LLOCAL;
            } else {
                p->r = lvalue_type(p->type.t) | VT_LOCAL;
            }
            p->r2 = VT_CONST;
            p->c.i = l;
        }
    }
}

#ifdef TCC_TARGET_ARM
/* find a register of class 'rc2' with at most one reference on stack.
 * If none, call get_reg(rc) */
ST_FUNC int get_reg_ex(int rc, int rc2)
{
    int r;
    SValue *p;
    
    for(r=0;r<NB_REGS;r++) {
        if (reg_classes[r] & rc2) {
            int n;
            n=0;
            for(p = vstack; p <= vtop; p++) {
                if ((p->r & VT_VALMASK) == r ||
                    (p->r2 & VT_VALMASK) == r)
                    n++;
            }
            if (n <= 1)
                return r;
        }
    }
    return get_reg(rc);
}
#endif

/* find a free register of class 'rc'. If none, save one register */
ST_FUNC int get_reg(int rc)
{
    int r;
    SValue *p;

    /* find a free register */
    for(r=0;r<NB_REGS;r++) {
        if (reg_classes[r] & rc) {
            for(p=vstack;p<=vtop;p++) {
                if ((p->r & VT_VALMASK) == r ||
                    (p->r2 & VT_VALMASK) == r)
                    goto notfound;
            }
            return r;
        }
    notfound: ;
    }
    
    /* no register left : free the first one on the stack (VERY
       IMPORTANT to start from the bottom to ensure that we don't
       spill registers used in gen_opi()) */
    for(p=vstack;p<=vtop;p++) {
        /* look at second register (if long long) */
        r = p->r2 & VT_VALMASK;
        if (r < VT_CONST && (reg_classes[r] & rc))
            goto save_found;
        r = p->r & VT_VALMASK;
        if (r < VT_CONST && (reg_classes[r] & rc)) {
        save_found:
            save_reg(r);
            return r;
        }
    }
    /* Should never comes here */
    return -1;
}

/* save registers up to (vtop - n) stack entry */
ST_FUNC void save_regs(int n)
{
    int r;
    SValue *p, *p1;
    p1 = vtop - n;
    for(p = vstack;p <= p1; p++) {
        r = p->r & VT_VALMASK;
        if (r < VT_CONST) {
            save_reg(r);
        }
    }
}

/* move register 's' (of type 't') to 'r', and flush previous value of r to memory
   if needed */
static void move_reg(int r, int s, int t)
{
    SValue sv;

    if (r != s) {
        save_reg(r);
        sv.type.t = t;
        sv.type.ref = NULL;
        sv.r = s;
        sv.c.i = 0;
        load(r, &sv);
    }
}

/* get address of vtop (vtop MUST BE an lvalue) */
ST_FUNC void gaddrof(void)
{
    if (vtop->r & VT_REF && !nocode_wanted)
        gv(RC_INT);
    vtop->r &= ~VT_LVAL;
    /* tricky: if saved lvalue, then we can go back to lvalue */
    if ((vtop->r & VT_VALMASK) == VT_LLOCAL)
        vtop->r = (vtop->r & ~(VT_VALMASK | VT_LVAL_TYPE)) | VT_LOCAL | VT_LVAL;


}

#ifdef CONFIG_TCC_BCHECK
/* generate lvalue bound code */
static void gbound(void)
{
    int lval_type;
    CType type1;

    vtop->r &= ~VT_MUSTBOUND;
    /* if lvalue, then use checking code before dereferencing */
    if (vtop->r & VT_LVAL) {
        /* if not VT_BOUNDED value, then make one */
        if (!(vtop->r & VT_BOUNDED)) {
            lval_type = vtop->r & (VT_LVAL_TYPE | VT_LVAL);
            /* must save type because we must set it to int to get pointer */
            type1 = vtop->type;
            vtop->type.t = VT_PTR;
            gaddrof();
            vpushi(0);
            gen_bounded_ptr_add();
            vtop->r |= lval_type;
            vtop->type = type1;
        }
        /* then check for dereferencing */
        gen_bounded_ptr_deref();
    }
}
#endif

/* store vtop a register belonging to class 'rc'. lvalues are
   converted to values. Cannot be used if cannot be converted to
   register value (such as structures). */
ST_FUNC int gv(int rc)
{
    int r, bit_pos, bit_size, size, align, i;
    int rc2;

    /* NOTE: get_reg can modify vstack[] */
    if (vtop->type.t & VT_BITFIELD) {
        CType type;
        int bits = 32;
        bit_pos = (vtop->type.t >> VT_STRUCT_SHIFT) & 0x3f;
        bit_size = (vtop->type.t >> (VT_STRUCT_SHIFT + 6)) & 0x3f;
        /* remove bit field info to avoid loops */
        vtop->type.t &= ~VT_BITFIELD & ((1 << VT_STRUCT_SHIFT) - 1);
        /* cast to int to propagate signedness in following ops */
        if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {
            type.t = VT_LLONG;
            bits = 64;
        } else
            type.t = VT_INT;
        if((vtop->type.t & VT_UNSIGNED) ||
           (vtop->type.t & VT_BTYPE) == VT_BOOL)
            type.t |= VT_UNSIGNED;
        gen_cast(&type);
        /* generate shifts */
        vpushi(bits - (bit_pos + bit_size));
        gen_op(TOK_SHL);
        vpushi(bits - bit_size);
        /* NOTE: transformed to SHR if unsigned */
        gen_op(TOK_SAR);
        r = gv(rc);
    } else {
        if (is_float(vtop->type.t) && 
            (vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
            Sym *sym;
            int *ptr;
            unsigned long offset;
#if defined(TCC_TARGET_ARM) && !defined(TCC_ARM_VFP)
            CValue check;
#endif
            
            /* XXX: unify with initializers handling ? */
            /* CPUs usually cannot use float constants, so we store them
               generically in data segment */
            size = type_size(&vtop->type, &align);
            offset = (data_section->data_offset + align - 1) & -align;
            data_section->data_offset = offset;
            /* XXX: not portable yet */
#if defined(__i386__) || defined(__x86_64__)
            /* Zero pad x87 tenbyte long doubles */
            if (size == LDOUBLE_SIZE) {
                vtop->c.tab[2] &= 0xffff;
#if LDOUBLE_SIZE == 16
                vtop->c.tab[3] = 0;
#endif
            }
#endif
            ptr = section_ptr_add(data_section, size);
            size = size >> 2;
#if defined(TCC_TARGET_ARM) && !defined(TCC_ARM_VFP)
            check.d = 1;
            if(check.tab[0])
                for(i=0;i<size;i++)
                    ptr[i] = vtop->c.tab[size-1-i];
            else
#endif
            for(i=0;i<size;i++)
                ptr[i] = vtop->c.tab[i];
            sym = get_sym_ref(&vtop->type, data_section, offset, size << 2);
            vtop->r |= VT_LVAL | VT_SYM;
            vtop->sym = sym;
            vtop->c.i = 0;
        }
#ifdef CONFIG_TCC_BCHECK
        if (vtop->r & VT_MUSTBOUND) 
            gbound();
#endif

        r = vtop->r & VT_VALMASK;
        rc2 = (rc & RC_FLOAT) ? RC_FLOAT : RC_INT;
#ifndef TCC_TARGET_ARM64
        if (rc == RC_IRET)
            rc2 = RC_LRET;
#ifdef TCC_TARGET_X86_64
        else if (rc == RC_FRET)
            rc2 = RC_QRET;
#endif
#endif

        /* need to reload if:
           - constant
           - lvalue (need to dereference pointer)
           - already a register, but not in the right class */
        if (r >= VT_CONST
         || (vtop->r & VT_LVAL)
         || !(reg_classes[r] & rc)
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
         || ((vtop->type.t & VT_BTYPE) == VT_QLONG && !(reg_classes[vtop->r2] & rc2))
         || ((vtop->type.t & VT_BTYPE) == VT_QFLOAT && !(reg_classes[vtop->r2] & rc2))
#else
         || ((vtop->type.t & VT_BTYPE) == VT_LLONG && !(reg_classes[vtop->r2] & rc2))
#endif
            )
        {
            r = get_reg(rc);
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            if (((vtop->type.t & VT_BTYPE) == VT_QLONG) || ((vtop->type.t & VT_BTYPE) == VT_QFLOAT)) {
                int addr_type = VT_LLONG, load_size = 8, load_type = ((vtop->type.t & VT_BTYPE) == VT_QLONG) ? VT_LLONG : VT_DOUBLE;
#else
            if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {
                int addr_type = VT_INT, load_size = 4, load_type = VT_INT;
                unsigned long long ll;
#endif
                int r2, original_type;
                original_type = vtop->type.t;
                /* two register type load : expand to two words
                   temporarily */
#if !defined(TCC_TARGET_ARM64) && !defined(TCC_TARGET_X86_64)
                if ((vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
                    /* load constant */
                    ll = vtop->c.i;
                    vtop->c.i = ll; /* first word */
                    load(r, vtop);
                    vtop->r = r; /* save register value */
                    vpushi(ll >> 32); /* second word */
                } else
#endif
                if (r >= VT_CONST || /* XXX: test to VT_CONST incorrect ? */
                           (vtop->r & VT_LVAL)) {
                    /* We do not want to modifier the long long
                       pointer here, so the safest (and less
                       efficient) is to save all the other registers
                       in the stack. XXX: totally inefficient. */
                    save_regs(1);
                    /* load from memory */
                    vtop->type.t = load_type;
                    load(r, vtop);
                    vdup();
                    vtop[-1].r = r; /* save register value */
                    /* increment pointer to get second word */
                    vtop->type.t = addr_type;
                    gaddrof();
                    vpushi(load_size);
                    gen_op('+');
                    vtop->r |= VT_LVAL;
                    vtop->type.t = load_type;
                } else {
                    /* move registers */
                    load(r, vtop);
                    vdup();
                    vtop[-1].r = r; /* save register value */
                    vtop->r = vtop[-1].r2;
                }
                /* Allocate second register. Here we rely on the fact that
                   get_reg() tries first to free r2 of an SValue. */
                r2 = get_reg(rc2);
                load(r2, vtop);
                vpop();
                /* write second register */
                vtop->r2 = r2;
                vtop->type.t = original_type;
            } else if ((vtop->r & VT_LVAL) && !is_float(vtop->type.t)) {
                int t1, t;
                /* lvalue of scalar type : need to use lvalue type
                   because of possible cast */
                t = vtop->type.t;
                t1 = t;
                /* compute memory access type */
                if (vtop->r & VT_REF)
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                    t = VT_PTR;
#else
                    t = VT_INT;
#endif
                else if (vtop->r & VT_LVAL_BYTE)
                    t = VT_BYTE;
                else if (vtop->r & VT_LVAL_SHORT)
                    t = VT_SHORT;
                if (vtop->r & VT_LVAL_UNSIGNED)
                    t |= VT_UNSIGNED;
                vtop->type.t = t;
                load(r, vtop);
                /* restore wanted type */
                vtop->type.t = t1;
            } else {
                /* one register type load */
                load(r, vtop);
            }
        }
        vtop->r = r;
#ifdef TCC_TARGET_C67
        /* uses register pairs for doubles */
        if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE) 
            vtop->r2 = r+1;
#endif
    }
    return r;
}

/* generate vtop[-1] and vtop[0] in resp. classes rc1 and rc2 */
ST_FUNC void gv2(int rc1, int rc2)
{
    int v;

    /* generate more generic register first. But VT_JMP or VT_CMP
       values must be generated first in all cases to avoid possible
       reload errors */
    v = vtop[0].r & VT_VALMASK;
    if (v != VT_CMP && (v & ~1) != VT_JMP && rc1 <= rc2) {
        vswap();
        gv(rc1);
        vswap();
        gv(rc2);
        /* test if reload is needed for first register */
        if ((vtop[-1].r & VT_VALMASK) >= VT_CONST) {
            vswap();
            gv(rc1);
            vswap();
        }
    } else {
        gv(rc2);
        vswap();
        gv(rc1);
        vswap();
        /* test if reload is needed for first register */
        if ((vtop[0].r & VT_VALMASK) >= VT_CONST) {
            gv(rc2);
        }
    }
}

#ifndef TCC_TARGET_ARM64
/* wrapper around RC_FRET to return a register by type */
static int rc_fret(int t)
{
#ifdef TCC_TARGET_X86_64
    if (t == VT_LDOUBLE) {
        return RC_ST0;
    }
#endif
    return RC_FRET;
}
#endif

/* wrapper around REG_FRET to return a register by type */
static int reg_fret(int t)
{
#ifdef TCC_TARGET_X86_64
    if (t == VT_LDOUBLE) {
        return TREG_ST0;
    }
#endif
    return REG_FRET;
}

/* expand long long on stack in two int registers */
static void lexpand(void)
{
    int u;

    u = vtop->type.t & (VT_DEFSIGN | VT_UNSIGNED);
    gv(RC_INT);
    vdup();
    vtop[0].r = vtop[-1].r2;
    vtop[0].r2 = VT_CONST;
    vtop[-1].r2 = VT_CONST;
    vtop[0].type.t = VT_INT | u;
    vtop[-1].type.t = VT_INT | u;
}

#ifdef TCC_TARGET_ARM
/* expand long long on stack */
ST_FUNC void lexpand_nr(void)
{
    int u,v;

    u = vtop->type.t & (VT_DEFSIGN | VT_UNSIGNED);
    vdup();
    vtop->r2 = VT_CONST;
    vtop->type.t = VT_INT | u;
    v=vtop[-1].r & (VT_VALMASK | VT_LVAL);
    if (v == VT_CONST) {
      vtop[-1].c.i = vtop->c.i;
      vtop->c.i = vtop->c.i >> 32;
      vtop->r = VT_CONST;
    } else if (v == (VT_LVAL|VT_CONST) || v == (VT_LVAL|VT_LOCAL)) {
      vtop->c.i += 4;
      vtop->r = vtop[-1].r;
    } else if (v > VT_CONST) {
      vtop--;
      lexpand();
    } else
      vtop->r = vtop[-1].r2;
    vtop[-1].r2 = VT_CONST;
    vtop[-1].type.t = VT_INT | u;
}
#endif

/* build a long long from two ints */
static void lbuild(int t)
{
    gv2(RC_INT, RC_INT);
    vtop[-1].r2 = vtop[0].r;
    vtop[-1].type.t = t;
    vpop();
}

/* rotate n first stack elements to the bottom 
   I1 ... In -> I2 ... In I1 [top is right]
*/
ST_FUNC void vrotb(int n)
{
    int i;
    SValue tmp;

    tmp = vtop[-n + 1];
    for(i=-n+1;i!=0;i++)
        vtop[i] = vtop[i+1];
    vtop[0] = tmp;
}

/* rotate the n elements before entry e towards the top
   I1 ... In ... -> In I1 ... I(n-1) ... [top is right]
 */
ST_FUNC void vrote(SValue *e, int n)
{
    int i;
    SValue tmp;

    tmp = *e;
    for(i = 0;i < n - 1; i++)
        e[-i] = e[-i - 1];
    e[-n + 1] = tmp;
}

/* rotate n first stack elements to the top
   I1 ... In -> In I1 ... I(n-1)  [top is right]
 */
ST_FUNC void vrott(int n)
{
    vrote(vtop, n);
}

/* pop stack value */
ST_FUNC void vpop(void)
{
    int v;
    v = vtop->r & VT_VALMASK;
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
    /* for x86, we need to pop the FP stack */
    if (v == TREG_ST0 && !nocode_wanted) {
        o(0xd8dd); /* fstp %st(0) */
    } else
#endif
    if (v == VT_JMP || v == VT_JMPI) {
        /* need to put correct jump if && or || without test */
        gsym(vtop->c.i);
    }
    vtop--;
}

/* convert stack entry to register and duplicate its value in another
   register */
static void gv_dup(void)
{
    int rc, t, r, r1;
    SValue sv;

    t = vtop->type.t;
    if ((t & VT_BTYPE) == VT_LLONG) {
        lexpand();
        gv_dup();
        vswap();
        vrotb(3);
        gv_dup();
        vrotb(4);
        /* stack: H L L1 H1 */
        lbuild(t);
        vrotb(3);
        vrotb(3);
        vswap();
        lbuild(t);
        vswap();
    } else {
        /* duplicate value */
        rc = RC_INT;
        sv.type.t = VT_INT;
        if (is_float(t)) {
            rc = RC_FLOAT;
#ifdef TCC_TARGET_X86_64
            if ((t & VT_BTYPE) == VT_LDOUBLE) {
                rc = RC_ST0;
            }
#endif
            sv.type.t = t;
        }
        r = gv(rc);
        r1 = get_reg(rc);
        sv.r = r;
        sv.c.i = 0;
        load(r1, &sv); /* move r to r1 */
        vdup();
        /* duplicates value */
        if (r != r1)
            vtop->r = r1;
    }
}

/* Generate value test
 *
 * Generate a test for any value (jump, comparison and integers) */
ST_FUNC int gvtst(int inv, int t)
{
    int v = vtop->r & VT_VALMASK;
    if (v != VT_CMP && v != VT_JMP && v != VT_JMPI) {
        vpushi(0);
        gen_op(TOK_NE);
    }
    if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
        /* constant jmp optimization */
        if ((vtop->c.i != 0) != inv)
            t = gjmp(t);
        vtop--;
        return t;
    }
    return gtst(inv, t);
}

#if !defined(TCC_TARGET_ARM64) && !defined(TCC_TARGET_X86_64)
/* generate CPU independent (unsigned) long long operations */
static void gen_opl(int op)
{
    int t, a, b, op1, c, i;
    int func;
    unsigned short reg_iret = REG_IRET;
    unsigned short reg_lret = REG_LRET;
    SValue tmp;

    switch(op) {
    case '/':
    case TOK_PDIV:
        func = TOK___divdi3;
        goto gen_func;
    case TOK_UDIV:
        func = TOK___udivdi3;
        goto gen_func;
    case '%':
        func = TOK___moddi3;
        goto gen_mod_func;
    case TOK_UMOD:
        func = TOK___umoddi3;
    gen_mod_func:
#ifdef TCC_ARM_EABI
        reg_iret = TREG_R2;
        reg_lret = TREG_R3;
#endif
    gen_func:
        /* call generic long long function */
        vpush_global_sym(&func_old_type, func);
        vrott(3);
        gfunc_call(2);
        vpushi(0);
        vtop->r = reg_iret;
        vtop->r2 = reg_lret;
        break;
    case '^':
    case '&':
    case '|':
    case '*':
    case '+':
    case '-':
        t = vtop->type.t;
        vswap();
        lexpand();
        vrotb(3);
        lexpand();
        /* stack: L1 H1 L2 H2 */
        tmp = vtop[0];
        vtop[0] = vtop[-3];
        vtop[-3] = tmp;
        tmp = vtop[-2];
        vtop[-2] = vtop[-3];
        vtop[-3] = tmp;
        vswap();
        /* stack: H1 H2 L1 L2 */
        if (op == '*') {
            vpushv(vtop - 1);
            vpushv(vtop - 1);
            gen_op(TOK_UMULL);
            lexpand();
            /* stack: H1 H2 L1 L2 ML MH */
            for(i=0;i<4;i++)
                vrotb(6);
            /* stack: ML MH H1 H2 L1 L2 */
            tmp = vtop[0];
            vtop[0] = vtop[-2];
            vtop[-2] = tmp;
            /* stack: ML MH H1 L2 H2 L1 */
            gen_op('*');
            vrotb(3);
            vrotb(3);
            gen_op('*');
            /* stack: ML MH M1 M2 */
            gen_op('+');
            gen_op('+');
        } else if (op == '+' || op == '-') {
            /* XXX: add non carry method too (for MIPS or alpha) */
            if (op == '+')
                op1 = TOK_ADDC1;
            else
                op1 = TOK_SUBC1;
            gen_op(op1);
            /* stack: H1 H2 (L1 op L2) */
            vrotb(3);
            vrotb(3);
            gen_op(op1 + 1); /* TOK_xxxC2 */
        } else {
            gen_op(op);
            /* stack: H1 H2 (L1 op L2) */
            vrotb(3);
            vrotb(3);
            /* stack: (L1 op L2) H1 H2 */
            gen_op(op);
            /* stack: (L1 op L2) (H1 op H2) */
        }
        /* stack: L H */
        lbuild(t);
        break;
    case TOK_SAR:
    case TOK_SHR:
    case TOK_SHL:
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            t = vtop[-1].type.t;
            vswap();
            lexpand();
            vrotb(3);
            /* stack: L H shift */
            c = (int)vtop->c.i;
            /* constant: simpler */
            /* NOTE: all comments are for SHL. the other cases are
               done by swaping words */
            vpop();
            if (op != TOK_SHL)
                vswap();
            if (c >= 32) {
                /* stack: L H */
                vpop();
                if (c > 32) {
                    vpushi(c - 32);
                    gen_op(op);
                }
                if (op != TOK_SAR) {
                    vpushi(0);
                } else {
                    gv_dup();
                    vpushi(31);
                    gen_op(TOK_SAR);
                }
                vswap();
            } else {
                vswap();
                gv_dup();
                /* stack: H L L */
                vpushi(c);
                gen_op(op);
                vswap();
                vpushi(32 - c);
                if (op == TOK_SHL)
                    gen_op(TOK_SHR);
                else
                    gen_op(TOK_SHL);
                vrotb(3);
                /* stack: L L H */
                vpushi(c);
                if (op == TOK_SHL)
                    gen_op(TOK_SHL);
                else
                    gen_op(TOK_SHR);
                gen_op('|');
            }
            if (op != TOK_SHL)
                vswap();
            lbuild(t);
        } else {
            /* XXX: should provide a faster fallback on x86 ? */
            switch(op) {
            case TOK_SAR:
                func = TOK___ashrdi3;
                goto gen_func;
            case TOK_SHR:
                func = TOK___lshrdi3;
                goto gen_func;
            case TOK_SHL:
                func = TOK___ashldi3;
                goto gen_func;
            }
        }
        break;
    default:
        /* compare operations */
        t = vtop->type.t;
        vswap();
        lexpand();
        vrotb(3);
        lexpand();
        /* stack: L1 H1 L2 H2 */
        tmp = vtop[-1];
        vtop[-1] = vtop[-2];
        vtop[-2] = tmp;
        /* stack: L1 L2 H1 H2 */
        /* compare high */
        op1 = op;
        /* when values are equal, we need to compare low words. since
           the jump is inverted, we invert the test too. */
        if (op1 == TOK_LT)
            op1 = TOK_LE;
        else if (op1 == TOK_GT)
            op1 = TOK_GE;
        else if (op1 == TOK_ULT)
            op1 = TOK_ULE;
        else if (op1 == TOK_UGT)
            op1 = TOK_UGE;
        a = 0;
        b = 0;
        gen_op(op1);
        if (op1 != TOK_NE) {
            a = gvtst(1, 0);
        }
        if (op != TOK_EQ) {
            /* generate non equal test */
            /* XXX: NOT PORTABLE yet */
            if (a == 0) {
                b = gvtst(0, 0);
            } else {
#if defined(TCC_TARGET_I386)
                b = psym(0x850f, 0);
#elif defined(TCC_TARGET_ARM)
                b = ind;
                o(0x1A000000 | encbranch(ind, 0, 1));
#elif defined(TCC_TARGET_C67) || defined(TCC_TARGET_ARM64)
                tcc_error("not implemented");
#else
#error not supported
#endif
            }
        }
        /* compare low. Always unsigned */
        op1 = op;
        if (op1 == TOK_LT)
            op1 = TOK_ULT;
        else if (op1 == TOK_LE)
            op1 = TOK_ULE;
        else if (op1 == TOK_GT)
            op1 = TOK_UGT;
        else if (op1 == TOK_GE)
            op1 = TOK_UGE;
        gen_op(op1);
        a = gvtst(1, a);
        gsym(b);
        vseti(VT_JMPI, a);
        break;
    }
}
#endif

static uint64_t gen_opic_sdiv(uint64_t a, uint64_t b)
{
    uint64_t x = (a >> 63 ? -a : a) / (b >> 63 ? -b : b);
    return (a ^ b) >> 63 ? -x : x;
}

static int gen_opic_lt(uint64_t a, uint64_t b)
{
    return (a ^ (uint64_t)1 << 63) < (b ^ (uint64_t)1 << 63);
}

/* handle integer constant optimizations and various machine
   independent opt */
static void gen_opic(int op)
{
    SValue *v1 = vtop - 1;
    SValue *v2 = vtop;
    int t1 = v1->type.t & VT_BTYPE;
    int t2 = v2->type.t & VT_BTYPE;
    int c1 = (v1->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
    int c2 = (v2->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
    uint64_t l1 = c1 ? v1->c.i : 0;
    uint64_t l2 = c2 ? v2->c.i : 0;
    int shm = (t1 == VT_LLONG) ? 63 : 31;

    if (t1 != VT_LLONG)
        l1 = ((uint32_t)l1 |
              (v1->type.t & VT_UNSIGNED ? 0 : -(l1 & 0x80000000)));
    if (t2 != VT_LLONG)
        l2 = ((uint32_t)l2 |
              (v2->type.t & VT_UNSIGNED ? 0 : -(l2 & 0x80000000)));

    if (c1 && c2) {
        switch(op) {
        case '+': l1 += l2; break;
        case '-': l1 -= l2; break;
        case '&': l1 &= l2; break;
        case '^': l1 ^= l2; break;
        case '|': l1 |= l2; break;
        case '*': l1 *= l2; break;

        case TOK_PDIV:
        case '/':
        case '%':
        case TOK_UDIV:
        case TOK_UMOD:
            /* if division by zero, generate explicit division */
            if (l2 == 0) {
                if (const_wanted)
                    tcc_error("division by zero in constant");
                goto general_case;
            }
            switch(op) {
            default: l1 = gen_opic_sdiv(l1, l2); break;
            case '%': l1 = l1 - l2 * gen_opic_sdiv(l1, l2); break;
            case TOK_UDIV: l1 = l1 / l2; break;
            case TOK_UMOD: l1 = l1 % l2; break;
            }
            break;
        case TOK_SHL: l1 <<= (l2 & shm); break;
        case TOK_SHR: l1 >>= (l2 & shm); break;
        case TOK_SAR:
            l1 = (l1 >> 63) ? ~(~l1 >> (l2 & shm)) : l1 >> (l2 & shm);
            break;
            /* tests */
        case TOK_ULT: l1 = l1 < l2; break;
        case TOK_UGE: l1 = l1 >= l2; break;
        case TOK_EQ: l1 = l1 == l2; break;
        case TOK_NE: l1 = l1 != l2; break;
        case TOK_ULE: l1 = l1 <= l2; break;
        case TOK_UGT: l1 = l1 > l2; break;
        case TOK_LT: l1 = gen_opic_lt(l1, l2); break;
        case TOK_GE: l1 = !gen_opic_lt(l1, l2); break;
        case TOK_LE: l1 = !gen_opic_lt(l2, l1); break;
        case TOK_GT: l1 = gen_opic_lt(l2, l1); break;
            /* logical */
        case TOK_LAND: l1 = l1 && l2; break;
        case TOK_LOR: l1 = l1 || l2; break;
        default:
            goto general_case;
        }
        v1->c.i = l1;
        vtop--;
    } else {
        /* if commutative ops, put c2 as constant */
        if (c1 && (op == '+' || op == '&' || op == '^' || 
                   op == '|' || op == '*')) {
            vswap();
            c2 = c1; //c = c1, c1 = c2, c2 = c;
            l2 = l1; //l = l1, l1 = l2, l2 = l;
        }
        if (!const_wanted &&
            c1 && ((l1 == 0 &&
                    (op == TOK_SHL || op == TOK_SHR || op == TOK_SAR)) ||
                   (l1 == -1 && op == TOK_SAR))) {
            /* treat (0 << x), (0 >> x) and (-1 >> x) as constant */
            vtop--;
        } else if (!const_wanted &&
                   c2 && ((l2 == 0 && (op == '&' || op == '*')) ||
                          (l2 == -1 && op == '|') ||
                          (l2 == 0xffffffff && t2 != VT_LLONG && op == '|') ||
                          (l2 == 1 && (op == '%' || op == TOK_UMOD)))) {
            /* treat (x & 0), (x * 0), (x | -1) and (x % 1) as constant */
            if (l2 == 1)
                vtop->c.i = 0;
            vswap();
            vtop--;
        } else if (c2 && (((op == '*' || op == '/' || op == TOK_UDIV ||
                          op == TOK_PDIV) &&
                           l2 == 1) ||
                          ((op == '+' || op == '-' || op == '|' || op == '^' ||
                            op == TOK_SHL || op == TOK_SHR || op == TOK_SAR) &&
                           l2 == 0) ||
                          (op == '&' &&
                           l2 == -1))) {
            /* filter out NOP operations like x*1, x-0, x&-1... */
            vtop--;
        } else if (c2 && (op == '*' || op == TOK_PDIV || op == TOK_UDIV)) {
            /* try to use shifts instead of muls or divs */
            if (l2 > 0 && (l2 & (l2 - 1)) == 0) {
                int n = -1;
                while (l2) {
                    l2 >>= 1;
                    n++;
                }
                vtop->c.i = n;
                if (op == '*')
                    op = TOK_SHL;
                else if (op == TOK_PDIV)
                    op = TOK_SAR;
                else
                    op = TOK_SHR;
            }
            goto general_case;
        } else if (c2 && (op == '+' || op == '-') &&
                   (((vtop[-1].r & (VT_VALMASK | VT_LVAL | VT_SYM)) == (VT_CONST | VT_SYM))
                    || (vtop[-1].r & (VT_VALMASK | VT_LVAL)) == VT_LOCAL)) {
            /* symbol + constant case */
            if (op == '-')
                l2 = -l2;
            vtop--;
            vtop->c.i += l2;
        } else {
        general_case:
            if (!nocode_wanted) {
                /* call low level op generator */
                if (t1 == VT_LLONG || t2 == VT_LLONG ||
                    (PTR_SIZE == 8 && (t1 == VT_PTR || t2 == VT_PTR)))
                    gen_opl(op);
                else
                    gen_opi(op);
            } else {
                vtop--;
            }
        }
    }
}

/* generate a floating point operation with constant propagation */
static void gen_opif(int op)
{
    int c1, c2;
    SValue *v1, *v2;
    long double f1, f2;

    v1 = vtop - 1;
    v2 = vtop;
    /* currently, we cannot do computations with forward symbols */
    c1 = (v1->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
    c2 = (v2->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
    if (c1 && c2) {
        if (v1->type.t == VT_FLOAT) {
            f1 = v1->c.f;
            f2 = v2->c.f;
        } else if (v1->type.t == VT_DOUBLE) {
            f1 = v1->c.d;
            f2 = v2->c.d;
        } else {
            f1 = v1->c.ld;
            f2 = v2->c.ld;
        }

        /* NOTE: we only do constant propagation if finite number (not
           NaN or infinity) (ANSI spec) */
        if (!ieee_finite(f1) || !ieee_finite(f2))
            goto general_case;

        switch(op) {
        case '+': f1 += f2; break;
        case '-': f1 -= f2; break;
        case '*': f1 *= f2; break;
        case '/': 
            if (f2 == 0.0) {
                if (const_wanted)
                    tcc_error("division by zero in constant");
                goto general_case;
            }
            f1 /= f2; 
            break;
            /* XXX: also handles tests ? */
        default:
            goto general_case;
        }
        /* XXX: overflow test ? */
        if (v1->type.t == VT_FLOAT) {
            v1->c.f = f1;
        } else if (v1->type.t == VT_DOUBLE) {
            v1->c.d = f1;
        } else {
            v1->c.ld = f1;
        }
        vtop--;
    } else {
    general_case:
        if (!nocode_wanted) {
            gen_opf(op);
        } else {
            vtop--;
        }
    }
}

static int pointed_size(CType *type)
{
    int align;
    return type_size(pointed_type(type), &align);
}

static void vla_runtime_pointed_size(CType *type)
{
    int align;
    vla_runtime_type_size(pointed_type(type), &align);
}

static inline int is_null_pointer(SValue *p)
{
    if ((p->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST)
        return 0;
    return ((p->type.t & VT_BTYPE) == VT_INT && (uint32_t)p->c.i == 0) ||
        ((p->type.t & VT_BTYPE) == VT_LLONG && p->c.i == 0) ||
        ((p->type.t & VT_BTYPE) == VT_PTR &&
         (PTR_SIZE == 4 ? (uint32_t)p->c.i == 0 : p->c.i == 0));
}

static inline int is_integer_btype(int bt)
{
    return (bt == VT_BYTE || bt == VT_SHORT || 
            bt == VT_INT || bt == VT_LLONG);
}

/* check types for comparison or subtraction of pointers */
static void check_comparison_pointer_types(SValue *p1, SValue *p2, int op)
{
    CType *type1, *type2, tmp_type1, tmp_type2;
    int bt1, bt2;
    
    /* null pointers are accepted for all comparisons as gcc */
    if (is_null_pointer(p1) || is_null_pointer(p2))
        return;
    type1 = &p1->type;
    type2 = &p2->type;
    bt1 = type1->t & VT_BTYPE;
    bt2 = type2->t & VT_BTYPE;
    /* accept comparison between pointer and integer with a warning */
    if ((is_integer_btype(bt1) || is_integer_btype(bt2)) && op != '-') {
        if (op != TOK_LOR && op != TOK_LAND )
            tcc_warning("comparison between pointer and integer");
        return;
    }

    /* both must be pointers or implicit function pointers */
    if (bt1 == VT_PTR) {
        type1 = pointed_type(type1);
    } else if (bt1 != VT_FUNC) 
        goto invalid_operands;

    if (bt2 == VT_PTR) {
        type2 = pointed_type(type2);
    } else if (bt2 != VT_FUNC) { 
    invalid_operands:
        tcc_error("invalid operands to binary %s", get_tok_str(op, NULL));
    }
    if ((type1->t & VT_BTYPE) == VT_VOID || 
        (type2->t & VT_BTYPE) == VT_VOID)
        return;
    tmp_type1 = *type1;
    tmp_type2 = *type2;
    tmp_type1.t &= ~(VT_DEFSIGN | VT_UNSIGNED | VT_CONSTANT | VT_VOLATILE);
    tmp_type2.t &= ~(VT_DEFSIGN | VT_UNSIGNED | VT_CONSTANT | VT_VOLATILE);
    if (!is_compatible_types(&tmp_type1, &tmp_type2)) {
        /* gcc-like error if '-' is used */
        if (op == '-')
            goto invalid_operands;
        else
            tcc_warning("comparison of distinct pointer types lacks a cast");
    }
}

/* generic gen_op: handles types problems */
ST_FUNC void gen_op(int op)
{
    int u, t1, t2, bt1, bt2, t;
    CType type1;

    t1 = vtop[-1].type.t;
    t2 = vtop[0].type.t;
    bt1 = t1 & VT_BTYPE;
    bt2 = t2 & VT_BTYPE;
        
    if (bt1 == VT_STRUCT || bt2 == VT_STRUCT) {
        tcc_error("operation on a struct");
    } else if (bt1 == VT_PTR || bt2 == VT_PTR) {
        /* at least one operand is a pointer */
        /* relationnal op: must be both pointers */
        if (op >= TOK_ULT && op <= TOK_LOR) {
            check_comparison_pointer_types(vtop - 1, vtop, op);
            /* pointers are handled are unsigned */
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            t = VT_LLONG | VT_UNSIGNED;
#else
            t = VT_INT | VT_UNSIGNED;
#endif
            goto std_op;
        }
        /* if both pointers, then it must be the '-' op */
        if (bt1 == VT_PTR && bt2 == VT_PTR) {
            if (op != '-')
                tcc_error("cannot use pointers here");
            check_comparison_pointer_types(vtop - 1, vtop, op);
            /* XXX: check that types are compatible */
            if (vtop[-1].type.t & VT_VLA) {
                vla_runtime_pointed_size(&vtop[-1].type);
            } else {
                vpushi(pointed_size(&vtop[-1].type));
            }
            vrott(3);
            gen_opic(op);
            /* set to integer type */
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            vtop->type.t = VT_LLONG;
#else
            vtop->type.t = VT_INT; 
#endif
            vswap();
            gen_op(TOK_PDIV);
        } else {
            /* exactly one pointer : must be '+' or '-'. */
            if (op != '-' && op != '+')
                tcc_error("cannot use pointers here");
            /* Put pointer as first operand */
            if (bt2 == VT_PTR) {
                vswap();
                swap(&t1, &t2);
            }
            type1 = vtop[-1].type;
            type1.t &= ~VT_ARRAY;
            if (vtop[-1].type.t & VT_VLA)
                vla_runtime_pointed_size(&vtop[-1].type);
            else {
                u = pointed_size(&vtop[-1].type);
                if (u < 0)
                    tcc_error("unknown array element size");
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                vpushll(u);
#else
                /* XXX: cast to int ? (long long case) */
                vpushi(u);
#endif
            }
            gen_op('*');
#if 0
/* #ifdef CONFIG_TCC_BCHECK
    The main reason to removing this code:
	#include <stdio.h>
	int main ()
	{
	    int v[10];
	    int i = 10;
	    int j = 9;
	    fprintf(stderr, "v+i-j  = %p\n", v+i-j);
	    fprintf(stderr, "v+(i-j)  = %p\n", v+(i-j));
	}
    When this code is on. then the output looks like 
	v+i-j = 0xfffffffe
	v+(i-j) = 0xbff84000
    */
            /* if evaluating constant expression, no code should be
               generated, so no bound check */
            if (tcc_state->do_bounds_check && !const_wanted) {
                /* if bounded pointers, we generate a special code to
                   test bounds */
                if (op == '-') {
                    vpushi(0);
                    vswap();
                    gen_op('-');
                }
                gen_bounded_ptr_add();
            } else
#endif
            {
                gen_opic(op);
            }
            /* put again type if gen_opic() swaped operands */
            vtop->type = type1;
        }
    } else if (is_float(bt1) || is_float(bt2)) {
        /* compute bigger type and do implicit casts */
        if (bt1 == VT_LDOUBLE || bt2 == VT_LDOUBLE) {
            t = VT_LDOUBLE;
        } else if (bt1 == VT_DOUBLE || bt2 == VT_DOUBLE) {
            t = VT_DOUBLE;
        } else {
            t = VT_FLOAT;
        }
        /* floats can only be used for a few operations */
        if (op != '+' && op != '-' && op != '*' && op != '/' &&
            (op < TOK_ULT || op > TOK_GT))
            tcc_error("invalid operands for binary operation");
        goto std_op;
    } else if (op == TOK_SHR || op == TOK_SAR || op == TOK_SHL) {
        t = bt1 == VT_LLONG ? VT_LLONG : VT_INT;
        if ((t1 & (VT_BTYPE | VT_UNSIGNED)) == (t | VT_UNSIGNED))
          t |= VT_UNSIGNED;
        goto std_op;
    } else if (bt1 == VT_LLONG || bt2 == VT_LLONG) {
        /* cast to biggest op */
        t = VT_LLONG;
        /* convert to unsigned if it does not fit in a long long */
        if ((t1 & (VT_BTYPE | VT_UNSIGNED)) == (VT_LLONG | VT_UNSIGNED) ||
            (t2 & (VT_BTYPE | VT_UNSIGNED)) == (VT_LLONG | VT_UNSIGNED))
            t |= VT_UNSIGNED;
        goto std_op;
    } else {
        /* integer operations */
        t = VT_INT;
        /* convert to unsigned if it does not fit in an integer */
        if ((t1 & (VT_BTYPE | VT_UNSIGNED)) == (VT_INT | VT_UNSIGNED) ||
            (t2 & (VT_BTYPE | VT_UNSIGNED)) == (VT_INT | VT_UNSIGNED))
            t |= VT_UNSIGNED;
    std_op:
        /* XXX: currently, some unsigned operations are explicit, so
           we modify them here */
        if (t & VT_UNSIGNED) {
            if (op == TOK_SAR)
                op = TOK_SHR;
            else if (op == '/')
                op = TOK_UDIV;
            else if (op == '%')
                op = TOK_UMOD;
            else if (op == TOK_LT)
                op = TOK_ULT;
            else if (op == TOK_GT)
                op = TOK_UGT;
            else if (op == TOK_LE)
                op = TOK_ULE;
            else if (op == TOK_GE)
                op = TOK_UGE;
        }
        vswap();
        type1.t = t;
        gen_cast(&type1);
        vswap();
        /* special case for shifts and long long: we keep the shift as
           an integer */
        if (op == TOK_SHR || op == TOK_SAR || op == TOK_SHL)
            type1.t = VT_INT;
        gen_cast(&type1);
        if (is_float(t))
            gen_opif(op);
        else
            gen_opic(op);
        if (op >= TOK_ULT && op <= TOK_GT) {
            /* relationnal op: the result is an int */
            vtop->type.t = VT_INT;
        } else {
            vtop->type.t = t;
        }
    }
    // Make sure that we have converted to an rvalue:
    if (vtop->r & VT_LVAL && !nocode_wanted)
        gv(is_float(vtop->type.t & VT_BTYPE) ? RC_FLOAT : RC_INT);
}

#ifndef TCC_TARGET_ARM
/* generic itof for unsigned long long case */
static void gen_cvt_itof1(int t)
{
#ifdef TCC_TARGET_ARM64
    gen_cvt_itof(t);
#else
    if ((vtop->type.t & (VT_BTYPE | VT_UNSIGNED)) == 
        (VT_LLONG | VT_UNSIGNED)) {

        if (t == VT_FLOAT)
            vpush_global_sym(&func_old_type, TOK___floatundisf);
#if LDOUBLE_SIZE != 8
        else if (t == VT_LDOUBLE)
            vpush_global_sym(&func_old_type, TOK___floatundixf);
#endif
        else
            vpush_global_sym(&func_old_type, TOK___floatundidf);
        vrott(2);
        gfunc_call(1);
        vpushi(0);
        vtop->r = reg_fret(t);
    } else {
        gen_cvt_itof(t);
    }
#endif
}
#endif

/* generic ftoi for unsigned long long case */
static void gen_cvt_ftoi1(int t)
{
#ifdef TCC_TARGET_ARM64
    gen_cvt_ftoi(t);
#else
    int st;

    if (t == (VT_LLONG | VT_UNSIGNED)) {
        /* not handled natively */
        st = vtop->type.t & VT_BTYPE;
        if (st == VT_FLOAT)
            vpush_global_sym(&func_old_type, TOK___fixunssfdi);
#if LDOUBLE_SIZE != 8
        else if (st == VT_LDOUBLE)
            vpush_global_sym(&func_old_type, TOK___fixunsxfdi);
#endif
        else
            vpush_global_sym(&func_old_type, TOK___fixunsdfdi);
        vrott(2);
        gfunc_call(1);
        vpushi(0);
        vtop->r = REG_IRET;
        vtop->r2 = REG_LRET;
    } else {
        gen_cvt_ftoi(t);
    }
#endif
}

/* force char or short cast */
static void force_charshort_cast(int t)
{
    int bits, dbt;
    dbt = t & VT_BTYPE;
    /* XXX: add optimization if lvalue : just change type and offset */
    if (dbt == VT_BYTE)
        bits = 8;
    else
        bits = 16;
    if (t & VT_UNSIGNED) {
        vpushi((1 << bits) - 1);
        gen_op('&');
    } else {
        bits = 32 - bits;
        vpushi(bits);
        gen_op(TOK_SHL);
        /* result must be signed or the SAR is converted to an SHL
           This was not the case when "t" was a signed short
           and the last value on the stack was an unsigned int */
        vtop->type.t &= ~VT_UNSIGNED;
        vpushi(bits);
        gen_op(TOK_SAR);
    }
}

/* cast 'vtop' to 'type'. Casting to bitfields is forbidden. */
static void gen_cast(CType *type)
{
    int sbt, dbt, sf, df, c, p;

    /* special delayed cast for char/short */
    /* XXX: in some cases (multiple cascaded casts), it may still
       be incorrect */
    if (vtop->r & VT_MUSTCAST) {
        vtop->r &= ~VT_MUSTCAST;
        force_charshort_cast(vtop->type.t);
    }

    /* bitfields first get cast to ints */
    if (vtop->type.t & VT_BITFIELD && !nocode_wanted) {
        gv(RC_INT);
    }

    dbt = type->t & (VT_BTYPE | VT_UNSIGNED);
    sbt = vtop->type.t & (VT_BTYPE | VT_UNSIGNED);

    if (sbt != dbt) {
        sf = is_float(sbt);
        df = is_float(dbt);
        c = (vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
        p = (vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == (VT_CONST | VT_SYM);
        if (c) {
            /* constant case: we can do it now */
            /* XXX: in ISOC, cannot do it if error in convert */
            if (sbt == VT_FLOAT)
                vtop->c.ld = vtop->c.f;
            else if (sbt == VT_DOUBLE)
                vtop->c.ld = vtop->c.d;

            if (df) {
                if ((sbt & VT_BTYPE) == VT_LLONG) {
                    if ((sbt & VT_UNSIGNED) || !(vtop->c.i >> 63))
                        vtop->c.ld = vtop->c.i;
                    else
                        vtop->c.ld = -(long double)-vtop->c.i;
                } else if(!sf) {
                    if ((sbt & VT_UNSIGNED) || !(vtop->c.i >> 31))
                        vtop->c.ld = (uint32_t)vtop->c.i;
                    else
                        vtop->c.ld = -(long double)-(uint32_t)vtop->c.i;
                }

                if (dbt == VT_FLOAT)
                    vtop->c.f = (float)vtop->c.ld;
                else if (dbt == VT_DOUBLE)
                    vtop->c.d = (double)vtop->c.ld;
            } else if (sf && dbt == (VT_LLONG|VT_UNSIGNED)) {
                vtop->c.i = vtop->c.ld;
            } else if (sf && dbt == VT_BOOL) {
                vtop->c.i = (vtop->c.ld != 0);
            } else {
                if(sf)
                    vtop->c.i = vtop->c.ld;
                else if (sbt == (VT_LLONG|VT_UNSIGNED))
                    ;
                else if (sbt & VT_UNSIGNED)
                    vtop->c.i = (uint32_t)vtop->c.i;
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                else if (sbt == VT_PTR)
                    ;
#endif
                else if (sbt != VT_LLONG)
                    vtop->c.i = ((uint32_t)vtop->c.i |
                                  -(vtop->c.i & 0x80000000));

                if (dbt == (VT_LLONG|VT_UNSIGNED))
                    ;
                else if (dbt == VT_BOOL)
                    vtop->c.i = (vtop->c.i != 0);
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                else if (dbt == VT_PTR)
                    ;
#endif
                else if (dbt != VT_LLONG) {
                    uint32_t m = ((dbt & VT_BTYPE) == VT_BYTE ? 0xff :
                                  (dbt & VT_BTYPE) == VT_SHORT ? 0xffff :
                                  0xffffffff);
                    vtop->c.i &= m;
                    if (!(dbt & VT_UNSIGNED))
                        vtop->c.i |= -(vtop->c.i & ((m >> 1) + 1));
                }
            }
        } else if (p && dbt == VT_BOOL) {
            vtop->r = VT_CONST;
            vtop->c.i = 1;
        } else if (!nocode_wanted) {
            /* non constant case: generate code */
            if (sf && df) {
                /* convert from fp to fp */
                gen_cvt_ftof(dbt);
            } else if (df) {
                /* convert int to fp */
                gen_cvt_itof1(dbt);
            } else if (sf) {
                /* convert fp to int */
                if (dbt == VT_BOOL) {
                     vpushi(0);
                     gen_op(TOK_NE);
                } else {
                    /* we handle char/short/etc... with generic code */
                    if (dbt != (VT_INT | VT_UNSIGNED) &&
                        dbt != (VT_LLONG | VT_UNSIGNED) &&
                        dbt != VT_LLONG)
                        dbt = VT_INT;
                    gen_cvt_ftoi1(dbt);
                    if (dbt == VT_INT && (type->t & (VT_BTYPE | VT_UNSIGNED)) != dbt) {
                        /* additional cast for char/short... */
                        vtop->type.t = dbt;
                        gen_cast(type);
                    }
                }
#if !defined(TCC_TARGET_ARM64) && !defined(TCC_TARGET_X86_64)
            } else if ((dbt & VT_BTYPE) == VT_LLONG) {
                if ((sbt & VT_BTYPE) != VT_LLONG && !nocode_wanted) {
                    /* scalar to long long */
                    /* machine independent conversion */
                    gv(RC_INT);
                    /* generate high word */
                    if (sbt == (VT_INT | VT_UNSIGNED)) {
                        vpushi(0);
                        gv(RC_INT);
                    } else {
                        if (sbt == VT_PTR) {
                            /* cast from pointer to int before we apply
                               shift operation, which pointers don't support*/
                            gen_cast(&int_type);
                        }
                        gv_dup();
                        vpushi(31);
                        gen_op(TOK_SAR);
                    }
                    /* patch second register */
                    vtop[-1].r2 = vtop->r;
                    vpop();
                }
#else
            } else if ((dbt & VT_BTYPE) == VT_LLONG ||
                       (dbt & VT_BTYPE) == VT_PTR ||
                       (dbt & VT_BTYPE) == VT_FUNC) {
                if ((sbt & VT_BTYPE) != VT_LLONG &&
                    (sbt & VT_BTYPE) != VT_PTR &&
                    (sbt & VT_BTYPE) != VT_FUNC && !nocode_wanted) {
                    /* need to convert from 32bit to 64bit */
                    gv(RC_INT);
                    if (sbt != (VT_INT | VT_UNSIGNED)) {
#if defined(TCC_TARGET_ARM64)
                        gen_cvt_sxtw();
#elif defined(TCC_TARGET_X86_64)
                        int r = gv(RC_INT);
                        /* x86_64 specific: movslq */
                        o(0x6348);
                        o(0xc0 + (REG_VALUE(r) << 3) + REG_VALUE(r));
#else
#error
#endif
                    }
                }
#endif
            } else if (dbt == VT_BOOL) {
                /* scalar to bool */
                vpushi(0);
                gen_op(TOK_NE);
            } else if ((dbt & VT_BTYPE) == VT_BYTE || 
                       (dbt & VT_BTYPE) == VT_SHORT) {
                if (sbt == VT_PTR) {
                    vtop->type.t = VT_INT;
                    tcc_warning("nonportable conversion from pointer to char/short");
                }
                force_charshort_cast(dbt);
            } else if ((dbt & VT_BTYPE) == VT_INT) {
                /* scalar to int */
                if (sbt == VT_LLONG && !nocode_wanted) {
                    /* from long long: just take low order word */
                    lexpand();
                    vpop();
                } 
                /* if lvalue and single word type, nothing to do because
                   the lvalue already contains the real type size (see
                   VT_LVAL_xxx constants) */
            }
        }
    } else if ((dbt & VT_BTYPE) == VT_PTR && !(vtop->r & VT_LVAL)) {
        /* if we are casting between pointer types,
           we must update the VT_LVAL_xxx size */
        vtop->r = (vtop->r & ~VT_LVAL_TYPE)
                  | (lvalue_type(type->ref->type.t) & VT_LVAL_TYPE);
    }
    vtop->type = *type;
}

/* return type size as known at compile time. Put alignment at 'a' */
ST_FUNC int type_size(CType *type, int *a)
{
    Sym *s;
    int bt;

    bt = type->t & VT_BTYPE;
    if (bt == VT_STRUCT) {
        /* struct/union */
        s = type->ref;
        *a = s->r;
        return s->c;
    } else if (bt == VT_PTR) {
        if (type->t & VT_ARRAY) {
            int ts;

            s = type->ref;
            ts = type_size(&s->type, a);

            if (ts < 0 && s->c < 0)
                ts = -ts;

            return ts * s->c;
        } else {
            *a = PTR_SIZE;
            return PTR_SIZE;
        }
    } else if (bt == VT_LDOUBLE) {
        *a = LDOUBLE_ALIGN;
        return LDOUBLE_SIZE;
    } else if (bt == VT_DOUBLE || bt == VT_LLONG) {
#ifdef TCC_TARGET_I386
#ifdef TCC_TARGET_PE
        *a = 8;
#else
        *a = 4;
#endif
#elif defined(TCC_TARGET_ARM)
#ifdef TCC_ARM_EABI
        *a = 8; 
#else
        *a = 4;
#endif
#else
        *a = 8;
#endif
        return 8;
    } else if (bt == VT_INT || bt == VT_FLOAT) {
        *a = 4;
        return 4;
    } else if (bt == VT_SHORT) {
        *a = 2;
        return 2;
    } else if (bt == VT_QLONG || bt == VT_QFLOAT) {
        *a = 8;
        return 16;
    } else if (bt == VT_ENUM) {
	*a = 4;
	/* Enums might be incomplete, so don't just return '4' here.  */
	return type->ref->c;
    } else {
        /* char, void, function, _Bool */
        *a = 1;
        return 1;
    }
}

/* push type size as known at runtime time on top of value stack. Put
   alignment at 'a' */
ST_FUNC void vla_runtime_type_size(CType *type, int *a)
{
    if (type->t & VT_VLA) {
        vset(&int_type, VT_LOCAL|VT_LVAL, type->ref->c);
    } else {
        vpushi(type_size(type, a));
    }
}

static void vla_sp_restore(void) {
    if (vlas_in_scope) {
        gen_vla_sp_restore(vla_sp_loc);
    }
}

static void vla_sp_restore_root(void) {
    if (vlas_in_scope) {
        gen_vla_sp_restore(vla_sp_root_loc);
    }
}

/* return the pointed type of t */
static inline CType *pointed_type(CType *type)
{
    return &type->ref->type;
}

/* modify type so that its it is a pointer to type. */
ST_FUNC void mk_pointer(CType *type)
{
    Sym *s;
    s = sym_push(SYM_FIELD, type, 0, -1);
    type->t = VT_PTR | (type->t & ~VT_TYPE);
    type->ref = s;
}

/* compare function types. OLD functions match any new functions */
static int is_compatible_func(CType *type1, CType *type2)
{
    Sym *s1, *s2;

    s1 = type1->ref;
    s2 = type2->ref;
    if (!is_compatible_types(&s1->type, &s2->type))
        return 0;
    /* check func_call */
    if (s1->a.func_call != s2->a.func_call)
        return 0;
    /* XXX: not complete */
    if (s1->c == FUNC_OLD || s2->c == FUNC_OLD)
        return 1;
    if (s1->c != s2->c)
        return 0;
    while (s1 != NULL) {
        if (s2 == NULL)
            return 0;
        if (!is_compatible_parameter_types(&s1->type, &s2->type))
            return 0;
        s1 = s1->next;
        s2 = s2->next;
    }
    if (s2)
        return 0;
    return 1;
}

/* return true if type1 and type2 are the same.  If unqualified is
   true, qualifiers on the types are ignored.

   - enums are not checked as gcc __builtin_types_compatible_p () 
 */
static int compare_types(CType *type1, CType *type2, int unqualified)
{
    int bt1, t1, t2;

    t1 = type1->t & VT_TYPE;
    t2 = type2->t & VT_TYPE;
    if (unqualified) {
        /* strip qualifiers before comparing */
        t1 &= ~(VT_CONSTANT | VT_VOLATILE);
        t2 &= ~(VT_CONSTANT | VT_VOLATILE);
    }
    /* Default Vs explicit signedness only matters for char */
    if ((t1 & VT_BTYPE) != VT_BYTE) {
        t1 &= ~VT_DEFSIGN;
        t2 &= ~VT_DEFSIGN;
    }
    /* XXX: bitfields ? */
    if (t1 != t2)
        return 0;
    /* test more complicated cases */
    bt1 = t1 & VT_BTYPE;
    if (bt1 == VT_PTR) {
        type1 = pointed_type(type1);
        type2 = pointed_type(type2);
        return is_compatible_types(type1, type2);
    } else if (bt1 == VT_STRUCT) {
        return (type1->ref == type2->ref);
    } else if (bt1 == VT_FUNC) {
        return is_compatible_func(type1, type2);
    } else {
        return 1;
    }
}

/* return true if type1 and type2 are exactly the same (including
   qualifiers). 
*/
static int is_compatible_types(CType *type1, CType *type2)
{
    return compare_types(type1,type2,0);
}

/* return true if type1 and type2 are the same (ignoring qualifiers).
*/
static int is_compatible_parameter_types(CType *type1, CType *type2)
{
    return compare_types(type1,type2,1);
}

/* print a type. If 'varstr' is not NULL, then the variable is also
   printed in the type */
/* XXX: union */
/* XXX: add array and function pointers */
static void type_to_str(char *buf, int buf_size, 
                 CType *type, const char *varstr)
{
    int bt, v, t;
    Sym *s, *sa;
    char buf1[256];
    const char *tstr;

    t = type->t & VT_TYPE;
    bt = t & VT_BTYPE;
    buf[0] = '\0';
    if (t & VT_CONSTANT)
        pstrcat(buf, buf_size, "const ");
    if (t & VT_VOLATILE)
        pstrcat(buf, buf_size, "volatile ");
    if ((t & (VT_DEFSIGN | VT_UNSIGNED)) == (VT_DEFSIGN | VT_UNSIGNED))
        pstrcat(buf, buf_size, "unsigned ");
    else if (t & VT_DEFSIGN)
        pstrcat(buf, buf_size, "signed ");
    switch(bt) {
    case VT_VOID:
        tstr = "void";
        goto add_tstr;
    case VT_BOOL:
        tstr = "_Bool";
        goto add_tstr;
    case VT_BYTE:
        tstr = "char";
        goto add_tstr;
    case VT_SHORT:
        tstr = "short";
        goto add_tstr;
    case VT_INT:
        tstr = "int";
        goto add_tstr;
    case VT_LONG:
        tstr = "long";
        goto add_tstr;
    case VT_LLONG:
        tstr = "long long";
        goto add_tstr;
    case VT_FLOAT:
        tstr = "float";
        goto add_tstr;
    case VT_DOUBLE:
        tstr = "double";
        goto add_tstr;
    case VT_LDOUBLE:
        tstr = "long double";
    add_tstr:
        pstrcat(buf, buf_size, tstr);
        break;
    case VT_ENUM:
    case VT_STRUCT:
        if (bt == VT_STRUCT)
            tstr = "struct ";
        else
            tstr = "enum ";
        pstrcat(buf, buf_size, tstr);
        v = type->ref->v & ~SYM_STRUCT;
        if (v >= SYM_FIRST_ANOM)
            pstrcat(buf, buf_size, "<anonymous>");
        else
            pstrcat(buf, buf_size, get_tok_str(v, NULL));
        break;
    case VT_FUNC:
        s = type->ref;
        type_to_str(buf, buf_size, &s->type, varstr);
        pstrcat(buf, buf_size, "(");
        sa = s->next;
        while (sa != NULL) {
            type_to_str(buf1, sizeof(buf1), &sa->type, NULL);
            pstrcat(buf, buf_size, buf1);
            sa = sa->next;
            if (sa)
                pstrcat(buf, buf_size, ", ");
        }
        pstrcat(buf, buf_size, ")");
        goto no_var;
    case VT_PTR:
        s = type->ref;
        if (t & VT_ARRAY) {
            snprintf(buf1, sizeof(buf1), "%s[%ld]", varstr ? varstr : "", s->c);
            type_to_str(buf, buf_size, &s->type, buf1);
            goto no_var;
        }
        pstrcpy(buf1, sizeof(buf1), "*");
        if (t & VT_CONSTANT)
            pstrcat(buf1, buf_size, "const ");
        if (t & VT_VOLATILE)
            pstrcat(buf1, buf_size, "volatile ");
        if (varstr)
            pstrcat(buf1, sizeof(buf1), varstr);
        type_to_str(buf, buf_size, &s->type, buf1);
        goto no_var;
    }
    if (varstr) {
        pstrcat(buf, buf_size, " ");
        pstrcat(buf, buf_size, varstr);
    }
 no_var: ;
}

/* verify type compatibility to store vtop in 'dt' type, and generate
   casts if needed. */
static void gen_assign_cast(CType *dt)
{
    CType *st, *type1, *type2, tmp_type1, tmp_type2;
    char buf1[256], buf2[256];
    int dbt, sbt;

    st = &vtop->type; /* source type */
    dbt = dt->t & VT_BTYPE;
    sbt = st->t & VT_BTYPE;
    if (sbt == VT_VOID || dbt == VT_VOID) {
	if (sbt == VT_VOID && dbt == VT_VOID)
	    ; /*
	      It is Ok if both are void
	      A test program:
	        void func1() {}
		void func2() {
		  return func1();
		}
	      gcc accepts this program
	      */
	else
    	    tcc_error("cannot cast from/to void");
    }
    if (dt->t & VT_CONSTANT)
        tcc_warning("assignment of read-only location");
    switch(dbt) {
    case VT_PTR:
        /* special cases for pointers */
        /* '0' can also be a pointer */
        if (is_null_pointer(vtop))
            goto type_ok;
        /* accept implicit pointer to integer cast with warning */
        if (is_integer_btype(sbt)) {
            tcc_warning("assignment makes pointer from integer without a cast");
            goto type_ok;
        }
        type1 = pointed_type(dt);
        /* a function is implicitely a function pointer */
        if (sbt == VT_FUNC) {
            if ((type1->t & VT_BTYPE) != VT_VOID &&
                !is_compatible_types(pointed_type(dt), st))
                tcc_warning("assignment from incompatible pointer type");
            goto type_ok;
        }
        if (sbt != VT_PTR)
            goto error;
        type2 = pointed_type(st);
        if ((type1->t & VT_BTYPE) == VT_VOID || 
            (type2->t & VT_BTYPE) == VT_VOID) {
            /* void * can match anything */
        } else {
            /* exact type match, except for unsigned */
            tmp_type1 = *type1;
            tmp_type2 = *type2;
            tmp_type1.t &= ~(VT_DEFSIGN | VT_UNSIGNED | VT_CONSTANT |
                             VT_VOLATILE);
            tmp_type2.t &= ~(VT_DEFSIGN | VT_UNSIGNED | VT_CONSTANT |
                             VT_VOLATILE);
            if (!is_compatible_types(&tmp_type1, &tmp_type2))
                tcc_warning("assignment from incompatible pointer type");
        }
        /* check const and volatile */
        if ((!(type1->t & VT_CONSTANT) && (type2->t & VT_CONSTANT)) ||
            (!(type1->t & VT_VOLATILE) && (type2->t & VT_VOLATILE)))
            tcc_warning("assignment discards qualifiers from pointer target type");
        break;
    case VT_BYTE:
    case VT_SHORT:
    case VT_INT:
    case VT_LLONG:
        if (sbt == VT_PTR || sbt == VT_FUNC) {
            tcc_warning("assignment makes integer from pointer without a cast");
        } else if (sbt == VT_STRUCT) {
            goto case_VT_STRUCT;
        }
        /* XXX: more tests */
        break;
    case VT_STRUCT:
    case_VT_STRUCT:
        tmp_type1 = *dt;
        tmp_type2 = *st;
        tmp_type1.t &= ~(VT_CONSTANT | VT_VOLATILE);
        tmp_type2.t &= ~(VT_CONSTANT | VT_VOLATILE);
        if (!is_compatible_types(&tmp_type1, &tmp_type2)) {
        error:
            type_to_str(buf1, sizeof(buf1), st, NULL);
            type_to_str(buf2, sizeof(buf2), dt, NULL);
            tcc_error("cannot cast '%s' to '%s'", buf1, buf2);
        }
        break;
    }
 type_ok:
    gen_cast(dt);
}

/* store vtop in lvalue pushed on stack */
ST_FUNC void vstore(void)
{
    int sbt, dbt, ft, r, t, size, align, bit_size, bit_pos, rc, delayed_cast;

    ft = vtop[-1].type.t;
    sbt = vtop->type.t & VT_BTYPE;
    dbt = ft & VT_BTYPE;
    if ((((sbt == VT_INT || sbt == VT_SHORT) && dbt == VT_BYTE) ||
         (sbt == VT_INT && dbt == VT_SHORT))
	&& !(vtop->type.t & VT_BITFIELD)) {
        /* optimize char/short casts */
        delayed_cast = VT_MUSTCAST;
        vtop->type.t = (ft & VT_TYPE & ~VT_BITFIELD &
                        ((1 << VT_STRUCT_SHIFT) - 1));
        /* XXX: factorize */
        if (ft & VT_CONSTANT)
            tcc_warning("assignment of read-only location");
    } else {
        delayed_cast = 0;
        if (!(ft & VT_BITFIELD))
            gen_assign_cast(&vtop[-1].type);
    }

    if (sbt == VT_STRUCT) {
        /* if structure, only generate pointer */
        /* structure assignment : generate memcpy */
        /* XXX: optimize if small size */
        if (!nocode_wanted) {
            size = type_size(&vtop->type, &align);

            /* destination */
            vswap();
            vtop->type.t = VT_PTR;
            gaddrof();

            /* address of memcpy() */
#ifdef TCC_ARM_EABI
            if(!(align & 7))
                vpush_global_sym(&func_old_type, TOK_memcpy8);
            else if(!(align & 3))
                vpush_global_sym(&func_old_type, TOK_memcpy4);
            else
#endif
            /* Use memmove, rather than memcpy, as dest and src may be same: */
            vpush_global_sym(&func_old_type, TOK_memmove);

            vswap();
            /* source */
            vpushv(vtop - 2);
            vtop->type.t = VT_PTR;
            gaddrof();
            /* type size */
            vpushi(size);
            gfunc_call(3);
        } else {
            vswap();
            vpop();
        }
        /* leave source on stack */
    } else if (ft & VT_BITFIELD) {
        /* bitfield store handling */

        /* save lvalue as expression result (example: s.b = s.a = n;) */
        vdup(), vtop[-1] = vtop[-2];

        bit_pos = (ft >> VT_STRUCT_SHIFT) & 0x3f;
        bit_size = (ft >> (VT_STRUCT_SHIFT + 6)) & 0x3f;
        /* remove bit field info to avoid loops */
        vtop[-1].type.t = ft & ~VT_BITFIELD & ((1 << VT_STRUCT_SHIFT) - 1);

        if((ft & VT_BTYPE) == VT_BOOL) {
            gen_cast(&vtop[-1].type);
            vtop[-1].type.t = (vtop[-1].type.t & ~VT_BTYPE) | (VT_BYTE | VT_UNSIGNED);
        }

        /* duplicate destination */
        vdup();
        vtop[-1] = vtop[-2];

        /* mask and shift source */
        if((ft & VT_BTYPE) != VT_BOOL) {
            if((ft & VT_BTYPE) == VT_LLONG) {
                vpushll((1ULL << bit_size) - 1ULL);
            } else {
                vpushi((1 << bit_size) - 1);
            }
            gen_op('&');
        }
        vpushi(bit_pos);
        gen_op(TOK_SHL);
        /* load destination, mask and or with source */
        vswap();
        if((ft & VT_BTYPE) == VT_LLONG) {
            vpushll(~(((1ULL << bit_size) - 1ULL) << bit_pos));
        } else {
            vpushi(~(((1 << bit_size) - 1) << bit_pos));
        }
        gen_op('&');
        gen_op('|');
        /* store result */
        vstore();
        /* ... and discard */
        vpop();

    } else {
        if (!nocode_wanted) {
#ifdef CONFIG_TCC_BCHECK
            /* bound check case */
            if (vtop[-1].r & VT_MUSTBOUND) {
                vswap();
                gbound();
                vswap();
            }
#endif
            rc = RC_INT;
            if (is_float(ft)) {
                rc = RC_FLOAT;
#ifdef TCC_TARGET_X86_64
                if ((ft & VT_BTYPE) == VT_LDOUBLE) {
                    rc = RC_ST0;
                } else if ((ft & VT_BTYPE) == VT_QFLOAT) {
                    rc = RC_FRET;
                }
#endif
            }
            r = gv(rc);  /* generate value */
            /* if lvalue was saved on stack, must read it */
            if ((vtop[-1].r & VT_VALMASK) == VT_LLOCAL) {
                SValue sv;
                t = get_reg(RC_INT);
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
                sv.type.t = VT_PTR;
#else
                sv.type.t = VT_INT;
#endif
                sv.r = VT_LOCAL | VT_LVAL;
                sv.c.i = vtop[-1].c.i;
                load(t, &sv);
                vtop[-1].r = t | VT_LVAL;
            }
            /* two word case handling : store second register at word + 4 (or +8 for x86-64)  */
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            if (((ft & VT_BTYPE) == VT_QLONG) || ((ft & VT_BTYPE) == VT_QFLOAT)) {
                int addr_type = VT_LLONG, load_size = 8, load_type = ((vtop->type.t & VT_BTYPE) == VT_QLONG) ? VT_LLONG : VT_DOUBLE;
#else
            if ((ft & VT_BTYPE) == VT_LLONG) {
                int addr_type = VT_INT, load_size = 4, load_type = VT_INT;
#endif
                vtop[-1].type.t = load_type;
                store(r, vtop - 1);
                vswap();
                /* convert to int to increment easily */
                vtop->type.t = addr_type;
                gaddrof();
                vpushi(load_size);
                gen_op('+');
                vtop->r |= VT_LVAL;
                vswap();
                vtop[-1].type.t = load_type;
                /* XXX: it works because r2 is spilled last ! */
                store(vtop->r2, vtop - 1);
            } else {
                store(r, vtop - 1);
            }
        }
        vswap();
        vtop--; /* NOT vpop() because on x86 it would flush the fp stack */
        vtop->r |= delayed_cast;
    }
}

/* post defines POST/PRE add. c is the token ++ or -- */
ST_FUNC void inc(int post, int c)
{
    test_lvalue();
    vdup(); /* save lvalue */
    if (post) {
        if (!nocode_wanted)
            gv_dup(); /* duplicate value */
        else
            vdup(); /* duplicate value */
        vrotb(3);
        vrotb(3);
    }
    /* add constant */
    vpushi(c - TOK_MID); 
    gen_op('+');
    vstore(); /* store value */
    if (post)
        vpop(); /* if post op, return saved value */
}

/* Parse GNUC __attribute__ extension. Currently, the following
   extensions are recognized:
   - aligned(n) : set data/function alignment.
   - packed : force data alignment to 1
   - section(x) : generate data/code in this section.
   - unused : currently ignored, but may be used someday.
   - regparm(n) : pass function parameters in registers (i386 only)
 */
static void parse_attribute(AttributeDef *ad)
{
    int t, n;
    
    while (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2) {
    next();
    skip('(');
    skip('(');
    while (tok != ')') {
        if (tok < TOK_IDENT)
            expect("attribute name");
        t = tok;
        next();
        switch(t) {
        case TOK_SECTION1:
        case TOK_SECTION2:
            skip('(');
            if (tok != TOK_STR)
                expect("section name");
            ad->section = find_section(tcc_state, (char *)tokc.str.data);
            next();
            skip(')');
            break;
        case TOK_ALIAS1:
        case TOK_ALIAS2:
            skip('(');
            if (tok != TOK_STR)
                expect("alias(\"target\")");
            ad->alias_target = /* save string as token, for later */
              tok_alloc((char*)tokc.str.data, tokc.str.size-1)->tok;
            next();
            skip(')');
            break;
	case TOK_VISIBILITY1:
	case TOK_VISIBILITY2:
            skip('(');
            if (tok != TOK_STR)
                expect("visibility(\"default|hidden|internal|protected\")");
	    if (!strcmp (tokc.str.data, "default"))
	        ad->a.visibility = STV_DEFAULT;
	    else if (!strcmp (tokc.str.data, "hidden"))
	        ad->a.visibility = STV_HIDDEN;
	    else if (!strcmp (tokc.str.data, "internal"))
	        ad->a.visibility = STV_INTERNAL;
	    else if (!strcmp (tokc.str.data, "protected"))
	        ad->a.visibility = STV_PROTECTED;
	    else
                expect("visibility(\"default|hidden|internal|protected\")");
            next();
            skip(')');
            break;
        case TOK_ALIGNED1:
        case TOK_ALIGNED2:
            if (tok == '(') {
                next();
                n = expr_const();
                if (n <= 0 || (n & (n - 1)) != 0) 
                    tcc_error("alignment must be a positive power of two");
                skip(')');
            } else {
                n = MAX_ALIGN;
            }
            ad->a.aligned = n;
            break;
        case TOK_PACKED1:
        case TOK_PACKED2:
            ad->a.packed = 1;
            break;
        case TOK_WEAK1:
        case TOK_WEAK2:
            ad->a.weak = 1;
            break;
        case TOK_UNUSED1:
        case TOK_UNUSED2:
            /* currently, no need to handle it because tcc does not
               track unused objects */
            break;
        case TOK_NORETURN1:
        case TOK_NORETURN2:
            /* currently, no need to handle it because tcc does not
               track unused objects */
            break;
        case TOK_CDECL1:
        case TOK_CDECL2:
        case TOK_CDECL3:
            ad->a.func_call = FUNC_CDECL;
            break;
        case TOK_STDCALL1:
        case TOK_STDCALL2:
        case TOK_STDCALL3:
            ad->a.func_call = FUNC_STDCALL;
            break;
#ifdef TCC_TARGET_I386
        case TOK_REGPARM1:
        case TOK_REGPARM2:
            skip('(');
            n = expr_const();
            if (n > 3) 
                n = 3;
            else if (n < 0)
                n = 0;
            if (n > 0)
                ad->a.func_call = FUNC_FASTCALL1 + n - 1;
            skip(')');
            break;
        case TOK_FASTCALL1:
        case TOK_FASTCALL2:
        case TOK_FASTCALL3:
            ad->a.func_call = FUNC_FASTCALLW;
            break;            
#endif
        case TOK_MODE:
            skip('(');
            switch(tok) {
                case TOK_MODE_DI:
                    ad->a.mode = VT_LLONG + 1;
                    break;
                case TOK_MODE_HI:
                    ad->a.mode = VT_SHORT + 1;
                    break;
                case TOK_MODE_SI:
                    ad->a.mode = VT_INT + 1;
                    break;
                default:
                    tcc_warning("__mode__(%s) not supported\n", get_tok_str(tok, NULL));
                    break;
            }
            next();
            skip(')');
            break;
        case TOK_DLLEXPORT:
            ad->a.func_export = 1;
            break;
        case TOK_DLLIMPORT:
            ad->a.func_import = 1;
            break;
        default:
            if (tcc_state->warn_unsupported)
                tcc_warning("'%s' attribute ignored", get_tok_str(t, NULL));
            /* skip parameters */
            if (tok == '(') {
                int parenthesis = 0;
                do {
                    if (tok == '(') 
                        parenthesis++;
                    else if (tok == ')') 
                        parenthesis--;
                    next();
                } while (parenthesis && tok != -1);
            }
            break;
        }
        if (tok != ',')
            break;
        next();
    }
    skip(')');
    skip(')');
    }
}

/* enum/struct/union declaration. u is either VT_ENUM or VT_STRUCT */
static void struct_decl(CType *type, AttributeDef *ad, int u)
{
    int a, v, size, align, maxalign, c, offset, flexible;
    int bit_size, bit_pos, bsize, bt, lbit_pos, prevbt;
    Sym *s, *ss, *ass, **ps;
    AttributeDef ad1;
    CType type1, btype;

    a = tok; /* save decl type */
    next();
    if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2) {
        parse_attribute(ad);
        next();
    } 
    if (tok != '{') {
        v = tok;
        next();
        /* struct already defined ? return it */
        if (v < TOK_IDENT)
            expect("struct/union/enum name");
        s = struct_find(v);
        if (s && (s->scope == local_scope || (tok != '{' && tok != ';'))) {
            if (s->type.t != a)
                tcc_error("redefinition of '%s'", get_tok_str(v, NULL));
            goto do_decl;
        }
    } else {
        v = anon_sym++;
    }
    type1.t = a;
    type1.ref = NULL;
    /* we put an undefined size for struct/union */
    s = sym_push(v | SYM_STRUCT, &type1, 0, -1);
    s->r = 0; /* default alignment is zero as gcc */
    /* put struct/union/enum name in type */
 do_decl:
    type->t = u;
    type->ref = s;
    
    if (tok == '{') {
        next();
        if (s->c != -1)
            tcc_error("struct/union/enum already defined");
        /* cannot be empty */
        c = 0;
        /* non empty enums are not allowed */
        if (a == TOK_ENUM) {
            for(;;) {
                v = tok;
                if (v < TOK_UIDENT)
                    expect("identifier");
                ss = sym_find(v);
                if (ss && !local_stack)
                    tcc_error("redefinition of enumerator '%s'",
                              get_tok_str(v, NULL));
                next();
                if (tok == '=') {
                    next();
                    c = expr_const();
                }
                /* enum symbols have static storage */
                ss = sym_push(v, &int_type, VT_CONST, c);
                ss->type.t |= VT_STATIC;
                if (tok != ',')
                    break;
                next();
                c++;
                /* NOTE: we accept a trailing comma */
                if (tok == '}')
                    break;
            }
            s->c = type_size(&int_type, &align);
            skip('}');
        } else {
            maxalign = 1;
            ps = &s->next;
            prevbt = VT_INT;
            bit_pos = 0;
            offset = 0;
            flexible = 0;
            while (tok != '}') {
                parse_btype(&btype, &ad1);
                while (1) {
		    if (flexible)
		        tcc_error("flexible array member '%s' not at the end of struct",
                              get_tok_str(v, NULL));
                    bit_size = -1;
                    v = 0;
                    type1 = btype;
                    if (tok != ':') {
                        type_decl(&type1, &ad1, &v, TYPE_DIRECT | TYPE_ABSTRACT);
                        if (v == 0) {
                    	    if ((type1.t & VT_BTYPE) != VT_STRUCT)
                        	expect("identifier");
                    	    else {
				int v = btype.ref->v;
				if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) < SYM_FIRST_ANOM) {
				    if (tcc_state->ms_extensions == 0)
                        		expect("identifier");
				}
                    	    }
                        }
                        if (type_size(&type1, &align) < 0) {
			    if ((a == TOK_STRUCT) && (type1.t & VT_ARRAY) && c)
			        flexible = 1;
			    else
			        tcc_error("field '%s' has incomplete type",
                                      get_tok_str(v, NULL));
                        }
                        if ((type1.t & VT_BTYPE) == VT_FUNC ||
                            (type1.t & (VT_TYPEDEF | VT_STATIC | VT_EXTERN | VT_INLINE)))
                            tcc_error("invalid type for '%s'", 
                                  get_tok_str(v, NULL));
                    }
                    if (tok == ':') {
                        next();
                        bit_size = expr_const();
                        /* XXX: handle v = 0 case for messages */
                        if (bit_size < 0)
                            tcc_error("negative width in bit-field '%s'", 
                                  get_tok_str(v, NULL));
                        if (v && bit_size == 0)
                            tcc_error("zero width for bit-field '%s'", 
                                  get_tok_str(v, NULL));
                    }
                    size = type_size(&type1, &align);
                    if (ad1.a.aligned) {
                        if (align < ad1.a.aligned)
                            align = ad1.a.aligned;
                    } else if (ad1.a.packed) {
                        align = 1;
                    } else if (*tcc_state->pack_stack_ptr) {
                        if (align > *tcc_state->pack_stack_ptr)
                            align = *tcc_state->pack_stack_ptr;
                    }
                    lbit_pos = 0;
                    if (bit_size >= 0) {
                        bt = type1.t & VT_BTYPE;
                        if (bt != VT_INT && 
                            bt != VT_BYTE && 
                            bt != VT_SHORT &&
                            bt != VT_BOOL &&
                            bt != VT_ENUM &&
                            bt != VT_LLONG)
                            tcc_error("bitfields must have scalar type");
                        bsize = size * 8;
                        if (bit_size > bsize) {
                            tcc_error("width of '%s' exceeds its type",
                                  get_tok_str(v, NULL));
                        } else if (bit_size == bsize) {
                            /* no need for bit fields */
                            bit_pos = 0;
                        } else if (bit_size == 0) {
                            /* XXX: what to do if only padding in a
                               structure ? */
                            /* zero size: means to pad */
                            bit_pos = 0;
                        } else {
                            /* we do not have enough room ?
                               did the type change?
                               is it a union? */
                            if ((bit_pos + bit_size) > bsize ||
                                bt != prevbt || a == TOK_UNION)
                                bit_pos = 0;
                            lbit_pos = bit_pos;
                            /* XXX: handle LSB first */
                            type1.t |= VT_BITFIELD | 
                                (bit_pos << VT_STRUCT_SHIFT) |
                                (bit_size << (VT_STRUCT_SHIFT + 6));
                            bit_pos += bit_size;
                        }
                        prevbt = bt;
                    } else {
                        bit_pos = 0;
                    }
                    if (v != 0 || (type1.t & VT_BTYPE) == VT_STRUCT) {
                        /* add new memory data only if starting
                           bit field */
                        if (lbit_pos == 0) {
                            if (a == TOK_STRUCT) {
                                c = (c + align - 1) & -align;
                                offset = c;
                                if (size > 0)
                                    c += size;
                            } else {
                                offset = 0;
                                if (size > c)
                                    c = size;
                            }
                            if (align > maxalign)
                                maxalign = align;
                        }
#if 0
                        printf("add field %s offset=%d", 
                               get_tok_str(v, NULL), offset);
                        if (type1.t & VT_BITFIELD) {
                            printf(" pos=%d size=%d", 
                                   (type1.t >> VT_STRUCT_SHIFT) & 0x3f,
                                   (type1.t >> (VT_STRUCT_SHIFT + 6)) & 0x3f);
                        }
                        printf("\n");
#endif
                    }
                    if (v == 0 && (type1.t & VT_BTYPE) == VT_STRUCT) {
                        ass = type1.ref;
                        while ((ass = ass->next) != NULL) {
                           ss = sym_push(ass->v, &ass->type, 0, offset + ass->c);
                           *ps = ss;
                           ps = &ss->next;
                        }
                    } else if (v) {
                        ss = sym_push(v | SYM_FIELD, &type1, 0, offset);
                        *ps = ss;
                        ps = &ss->next;
                    }
                    if (tok == ';' || tok == TOK_EOF)
                        break;
                    skip(',');
                }
                skip(';');
            }
            skip('}');
            /* store size and alignment */
            s->c = (c + maxalign - 1) & -maxalign; 
            s->r = maxalign;
        }
    }
}

/* return 1 if basic type is a type size (short, long, long long) */
ST_FUNC int is_btype_size(int bt)
{
  return bt == VT_SHORT || bt == VT_LONG || bt == VT_LLONG;
}

/* Add type qualifiers to a type. If the type is an array then the qualifiers
   are added to the element type, copied because it could be a typedef. */
static void parse_btype_qualify(CType *type, int qualifiers)
{
    while (type->t & VT_ARRAY) {
        type->ref = sym_push(SYM_FIELD, &type->ref->type, 0, type->ref->c);
        type = &type->ref->type;
    }
    type->t |= qualifiers;
}

/* return 0 if no type declaration. otherwise, return the basic type
   and skip it. 
 */
static int parse_btype(CType *type, AttributeDef *ad)
{
    int t, u, bt_size, complete, type_found, typespec_found;
    Sym *s;
    CType type1;

    memset(ad, 0, sizeof(AttributeDef));
    complete = 0;
    type_found = 0;
    typespec_found = 0;
    t = 0;
    while(1) {
        switch(tok) {
        case TOK_EXTENSION:
            /* currently, we really ignore extension */
            next();
            continue;

            /* basic types */
        case TOK_CHAR:
            u = VT_BYTE;
        basic_type:
            next();
        basic_type1:
            if (complete)
                tcc_error("too many basic types");
            t |= u;
            bt_size = is_btype_size (u & VT_BTYPE);
            if (u == VT_INT || (!bt_size && !(t & VT_TYPEDEF)))
                complete = 1;
            typespec_found = 1;
            break;
        case TOK_VOID:
            u = VT_VOID;
            goto basic_type;
        case TOK_SHORT:
            u = VT_SHORT;
            goto basic_type;
        case TOK_INT:
            u = VT_INT;
            goto basic_type;
        case TOK_LONG:
            next();
            if ((t & VT_BTYPE) == VT_DOUBLE) {
#ifndef TCC_TARGET_PE
                t = (t & ~VT_BTYPE) | VT_LDOUBLE;
#endif
            } else if ((t & VT_BTYPE) == VT_LONG) {
                t = (t & ~VT_BTYPE) | VT_LLONG;
            } else {
                u = VT_LONG;
                goto basic_type1;
            }
            break;
#ifdef TCC_TARGET_ARM64
        case TOK_UINT128:
            /* GCC's __uint128_t appears in some Linux header files. Make it a
               synonym for long double to get the size and alignment right. */
            u = VT_LDOUBLE;
            goto basic_type;
#endif
        case TOK_BOOL:
            u = VT_BOOL;
            goto basic_type;
        case TOK_FLOAT:
            u = VT_FLOAT;
            goto basic_type;
        case TOK_DOUBLE:
            next();
            if ((t & VT_BTYPE) == VT_LONG) {
#ifdef TCC_TARGET_PE
                t = (t & ~VT_BTYPE) | VT_DOUBLE;
#else
                t = (t & ~VT_BTYPE) | VT_LDOUBLE;
#endif
            } else {
                u = VT_DOUBLE;
                goto basic_type1;
            }
            break;
        case TOK_ENUM:
            struct_decl(&type1, ad, VT_ENUM);
        basic_type2:
            u = type1.t;
            type->ref = type1.ref;
            goto basic_type1;
        case TOK_STRUCT:
        case TOK_UNION:
            struct_decl(&type1, ad, VT_STRUCT);
            goto basic_type2;

            /* type modifiers */
        case TOK_CONST1:
        case TOK_CONST2:
        case TOK_CONST3:
            type->t = t;
            parse_btype_qualify(type, VT_CONSTANT);
            t = type->t;
            next();
            break;
        case TOK_VOLATILE1:
        case TOK_VOLATILE2:
        case TOK_VOLATILE3:
            type->t = t;
            parse_btype_qualify(type, VT_VOLATILE);
            t = type->t;
            next();
            break;
        case TOK_SIGNED1:
        case TOK_SIGNED2:
        case TOK_SIGNED3:
            if ((t & (VT_DEFSIGN|VT_UNSIGNED)) == (VT_DEFSIGN|VT_UNSIGNED))
                tcc_error("signed and unsigned modifier");
            typespec_found = 1;
            t |= VT_DEFSIGN;
            next();
            break;
        case TOK_REGISTER:
        case TOK_AUTO:
        case TOK_RESTRICT1:
        case TOK_RESTRICT2:
        case TOK_RESTRICT3:
            next();
            break;
        case TOK_UNSIGNED:
            if ((t & (VT_DEFSIGN|VT_UNSIGNED)) == VT_DEFSIGN)
                tcc_error("signed and unsigned modifier");
            t |= VT_DEFSIGN | VT_UNSIGNED;
            next();
            typespec_found = 1;
            break;

            /* storage */
        case TOK_EXTERN:
            t |= VT_EXTERN;
            next();
            break;
        case TOK_STATIC:
            t |= VT_STATIC;
            next();
            break;
        case TOK_TYPEDEF:
            t |= VT_TYPEDEF;
            next();
            break;
        case TOK_INLINE1:
        case TOK_INLINE2:
        case TOK_INLINE3:
            t |= VT_INLINE;
            next();
            break;

            /* GNUC attribute */
        case TOK_ATTRIBUTE1:
        case TOK_ATTRIBUTE2:
            parse_attribute(ad);
            if (ad->a.mode) {
                u = ad->a.mode -1;
                t = (t & ~VT_BTYPE) | u;
            }
            break;
            /* GNUC typeof */
        case TOK_TYPEOF1:
        case TOK_TYPEOF2:
        case TOK_TYPEOF3:
            next();
            parse_expr_type(&type1);
            /* remove all storage modifiers except typedef */
            type1.t &= ~(VT_STORAGE&~VT_TYPEDEF);
            goto basic_type2;
        default:
            if (typespec_found)
                goto the_end;
            s = sym_find(tok);
            if (!s || !(s->type.t & VT_TYPEDEF))
                goto the_end;

            type->t = ((s->type.t & ~VT_TYPEDEF) |
                       (t & ~(VT_CONSTANT | VT_VOLATILE)));
            type->ref = s->type.ref;
            if (t & (VT_CONSTANT | VT_VOLATILE))
                parse_btype_qualify(type, t & (VT_CONSTANT | VT_VOLATILE));
            t = type->t;

            if (s->r) {
                /* get attributes from typedef */
                if (0 == ad->a.aligned)
                    ad->a.aligned = s->a.aligned;
                if (0 == ad->a.func_call)
                    ad->a.func_call = s->a.func_call;
                ad->a.packed |= s->a.packed;
            }
            next();
            typespec_found = 1;
            break;
        }
        type_found = 1;
    }
the_end:
    if (tcc_state->char_is_unsigned) {
        if ((t & (VT_DEFSIGN|VT_BTYPE)) == VT_BYTE)
            t |= VT_UNSIGNED;
    }

    /* long is never used as type */
    if ((t & VT_BTYPE) == VT_LONG)
#if (!defined TCC_TARGET_X86_64 && !defined TCC_TARGET_ARM64) || \
    defined TCC_TARGET_PE
        t = (t & ~VT_BTYPE) | VT_INT;
#else
        t = (t & ~VT_BTYPE) | VT_LLONG;
#endif
    type->t = t;
    return type_found;
}

/* convert a function parameter type (array to pointer and function to
   function pointer) */
static inline void convert_parameter_type(CType *pt)
{
    /* remove const and volatile qualifiers (XXX: const could be used
       to indicate a const function parameter */
    pt->t &= ~(VT_CONSTANT | VT_VOLATILE);
    /* array must be transformed to pointer according to ANSI C */
    pt->t &= ~VT_ARRAY;
    if ((pt->t & VT_BTYPE) == VT_FUNC) {
        mk_pointer(pt);
    }
}

ST_FUNC void parse_asm_str(CString *astr)
{
    skip('(');
    /* read the string */
    if (tok != TOK_STR)
        expect("string constant");
    cstr_new(astr);
    while (tok == TOK_STR) {
        /* XXX: add \0 handling too ? */
        cstr_cat(astr, tokc.str.data, -1);
        next();
    }
    cstr_ccat(astr, '\0');
}

/* Parse an asm label and return the token */
static int asm_label_instr(void)
{
    int v;
    CString astr;

    next();
    parse_asm_str(&astr);
    skip(')');
#ifdef ASM_DEBUG
    printf("asm_alias: \"%s\"\n", (char *)astr.data);
#endif
    v = tok_alloc(astr.data, astr.size - 1)->tok;
    cstr_free(&astr);
    return v;
}

static void post_type(CType *type, AttributeDef *ad)
{
    int n, l, t1, arg_size, align;
    Sym **plast, *s, *first;
    AttributeDef ad1;
    CType pt;

    if (tok == '(') {
        /* function declaration */
        next();
        l = 0;
        first = NULL;
        plast = &first;
        arg_size = 0;
        if (tok != ')') {
            for(;;) {
                /* read param name and compute offset */
                if (l != FUNC_OLD) {
                    if (!parse_btype(&pt, &ad1)) {
                        if (l) {
                            tcc_error("invalid type");
                        } else {
                            l = FUNC_OLD;
                            goto old_proto;
                        }
                    }
                    l = FUNC_NEW;
                    if ((pt.t & VT_BTYPE) == VT_VOID && tok == ')')
                        break;
                    type_decl(&pt, &ad1, &n, TYPE_DIRECT | TYPE_ABSTRACT);
                    if ((pt.t & VT_BTYPE) == VT_VOID)
                        tcc_error("parameter declared as void");
                    arg_size += (type_size(&pt, &align) + PTR_SIZE - 1) / PTR_SIZE;
                } else {
                old_proto:
                    n = tok;
                    if (n < TOK_UIDENT)
                        expect("identifier");
                    pt.t = VT_INT;
                    next();
                }
                convert_parameter_type(&pt);
                s = sym_push(n | SYM_FIELD, &pt, 0, 0);
                *plast = s;
                plast = &s->next;
                if (tok == ')')
                    break;
                skip(',');
                if (l == FUNC_NEW && tok == TOK_DOTS) {
                    l = FUNC_ELLIPSIS;
                    next();
                    break;
                }
            }
        }
        /* if no parameters, then old type prototype */
        if (l == 0)
            l = FUNC_OLD;
        skip(')');
        /* NOTE: const is ignored in returned type as it has a special
           meaning in gcc / C++ */
        type->t &= ~VT_CONSTANT; 
        /* some ancient pre-K&R C allows a function to return an array
           and the array brackets to be put after the arguments, such 
           that "int c()[]" means something like "int[] c()" */
        if (tok == '[') {
            next();
            skip(']'); /* only handle simple "[]" */
            type->t |= VT_PTR;
        }
        /* we push a anonymous symbol which will contain the function prototype */
        ad->a.func_args = arg_size;
        s = sym_push(SYM_FIELD, type, 0, l);
        s->a = ad->a;
        s->next = first;
        type->t = VT_FUNC;
        type->ref = s;
    } else if (tok == '[') {
        /* array definition */
        next();
        if (tok == TOK_RESTRICT1)
            next();
        n = -1;
        t1 = 0;
        if (tok != ']') {
            if (!local_stack || nocode_wanted)
                 vpushi(expr_const());
            else gexpr();
            if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
                n = vtop->c.i;
                if (n < 0)
                    tcc_error("invalid array size");
            } else {
                if (!is_integer_btype(vtop->type.t & VT_BTYPE))
                    tcc_error("size of variable length array should be an integer");
                t1 = VT_VLA;
            }
        }
        skip(']');
        /* parse next post type */
        post_type(type, ad);
        if (type->t == VT_FUNC)
            tcc_error("declaration of an array of functions");
        t1 |= type->t & VT_VLA;
        
        if (t1 & VT_VLA) {
            loc -= type_size(&int_type, &align);
            loc &= -align;
            n = loc;

            vla_runtime_type_size(type, &align);
            gen_op('*');
            vset(&int_type, VT_LOCAL|VT_LVAL, n);
            vswap();
            vstore();
        }
        if (n != -1)
            vpop();
                
        /* we push an anonymous symbol which will contain the array
           element type */
        s = sym_push(SYM_FIELD, type, 0, n);
        type->t = (t1 ? VT_VLA : VT_ARRAY) | VT_PTR;
        type->ref = s;
    }
}

/* Parse a type declaration (except basic type), and return the type
   in 'type'. 'td' is a bitmask indicating which kind of type decl is
   expected. 'type' should contain the basic type. 'ad' is the
   attribute definition of the basic type. It can be modified by
   type_decl(). 
 */
static void type_decl(CType *type, AttributeDef *ad, int *v, int td)
{
    Sym *s;
    CType type1, *type2;
    int qualifiers, storage;

    while (tok == '*') {
        qualifiers = 0;
    redo:
        next();
        switch(tok) {
        case TOK_CONST1:
        case TOK_CONST2:
        case TOK_CONST3:
            qualifiers |= VT_CONSTANT;
            goto redo;
        case TOK_VOLATILE1:
        case TOK_VOLATILE2:
        case TOK_VOLATILE3:
            qualifiers |= VT_VOLATILE;
            goto redo;
        case TOK_RESTRICT1:
        case TOK_RESTRICT2:
        case TOK_RESTRICT3:
            goto redo;
        }
        mk_pointer(type);
        type->t |= qualifiers;
    }
    
    /* XXX: clarify attribute handling */
    if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
        parse_attribute(ad);

    /* recursive type */
    /* XXX: incorrect if abstract type for functions (e.g. 'int ()') */
    type1.t = 0; /* XXX: same as int */
    if (tok == '(') {
        next();
        /* XXX: this is not correct to modify 'ad' at this point, but
           the syntax is not clear */
        if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
            parse_attribute(ad);
        type_decl(&type1, ad, v, td);
        skip(')');
    } else {
        /* type identifier */
        if (tok >= TOK_IDENT && (td & TYPE_DIRECT)) {
            *v = tok;
            next();
        } else {
            if (!(td & TYPE_ABSTRACT))
                expect("identifier");
            *v = 0;
        }
    }
    storage = type->t & VT_STORAGE;
    type->t &= ~VT_STORAGE;
    if (storage & VT_STATIC) {
        int saved_nocode_wanted = nocode_wanted;
        nocode_wanted = 1;
        post_type(type, ad);
        nocode_wanted = saved_nocode_wanted;
    } else
        post_type(type, ad);
    type->t |= storage;
    if (tok == TOK_ATTRIBUTE1 || tok == TOK_ATTRIBUTE2)
        parse_attribute(ad);
    
    if (!type1.t)
        return;
    /* append type at the end of type1 */
    type2 = &type1;
    for(;;) {
        s = type2->ref;
        type2 = &s->type;
        if (!type2->t) {
            *type2 = *type;
            break;
        }
    }
    *type = type1;
}

/* compute the lvalue VT_LVAL_xxx needed to match type t. */
ST_FUNC int lvalue_type(int t)
{
    int bt, r;
    r = VT_LVAL;
    bt = t & VT_BTYPE;
    if (bt == VT_BYTE || bt == VT_BOOL)
        r |= VT_LVAL_BYTE;
    else if (bt == VT_SHORT)
        r |= VT_LVAL_SHORT;
    else
        return r;
    if (t & VT_UNSIGNED)
        r |= VT_LVAL_UNSIGNED;
    return r;
}

/* indirection with full error checking and bound check */
ST_FUNC void indir(void)
{
    if ((vtop->type.t & VT_BTYPE) != VT_PTR) {
        if ((vtop->type.t & VT_BTYPE) == VT_FUNC)
            return;
        expect("pointer");
    }
    if ((vtop->r & VT_LVAL) && !nocode_wanted)
        gv(RC_INT);
    vtop->type = *pointed_type(&vtop->type);
    /* Arrays and functions are never lvalues */
    if (!(vtop->type.t & VT_ARRAY) && !(vtop->type.t & VT_VLA)
        && (vtop->type.t & VT_BTYPE) != VT_FUNC) {
        vtop->r |= lvalue_type(vtop->type.t);
        /* if bound checking, the referenced pointer must be checked */
#ifdef CONFIG_TCC_BCHECK
        if (tcc_state->do_bounds_check)
            vtop->r |= VT_MUSTBOUND;
#endif
    }
}

/* pass a parameter to a function and do type checking and casting */
static void gfunc_param_typed(Sym *func, Sym *arg)
{
    int func_type;
    CType type;

    func_type = func->c;
    if (func_type == FUNC_OLD ||
        (func_type == FUNC_ELLIPSIS && arg == NULL)) {
        /* default casting : only need to convert float to double */
        if ((vtop->type.t & VT_BTYPE) == VT_FLOAT) {
            type.t = VT_DOUBLE;
            gen_cast(&type);
        } else if (vtop->type.t & VT_BITFIELD) {
            type.t = vtop->type.t & (VT_BTYPE | VT_UNSIGNED);
            gen_cast(&type);
        }
    } else if (arg == NULL) {
        tcc_error("too many arguments to function");
    } else {
        type = arg->type;
        type.t &= ~VT_CONSTANT; /* need to do that to avoid false warning */
        gen_assign_cast(&type);
    }
}

/* parse an expression of the form '(type)' or '(expr)' and return its
   type */
static void parse_expr_type(CType *type)
{
    int n;
    AttributeDef ad;

    skip('(');
    if (parse_btype(type, &ad)) {
        type_decl(type, &ad, &n, TYPE_ABSTRACT);
    } else {
        expr_type(type);
    }
    skip(')');
}

static void parse_type(CType *type)
{
    AttributeDef ad;
    int n;

    if (!parse_btype(type, &ad)) {
        expect("type");
    }
    type_decl(type, &ad, &n, TYPE_ABSTRACT);
}

static void vpush_tokc(int t)
{
    CType type;
    type.t = t;
    type.ref = 0;
    vsetc(&type, VT_CONST, &tokc);
}

ST_FUNC void unary(void)
{
    int n, t, align, size, r, sizeof_caller;
    CType type;
    Sym *s;
    AttributeDef ad;
    static int in_sizeof = 0;

    sizeof_caller = in_sizeof;
    in_sizeof = 0;
    /* XXX: GCC 2.95.3 does not generate a table although it should be
       better here */
 tok_next:
    switch(tok) {
    case TOK_EXTENSION:
        next();
        goto tok_next;
    case TOK_CINT:
    case TOK_CCHAR: 
    case TOK_LCHAR:
        vpushi(tokc.i);
        next();
        break;
    case TOK_CUINT:
        vpush_tokc(VT_INT | VT_UNSIGNED);
        next();
        break;
    case TOK_CLLONG:
        vpush_tokc(VT_LLONG);
        next();
        break;
    case TOK_CULLONG:
        vpush_tokc(VT_LLONG | VT_UNSIGNED);
        next();
        break;
    case TOK_CFLOAT:
        vpush_tokc(VT_FLOAT);
        next();
        break;
    case TOK_CDOUBLE:
        vpush_tokc(VT_DOUBLE);
        next();
        break;
    case TOK_CLDOUBLE:
        vpush_tokc(VT_LDOUBLE);
        next();
        break;
    case TOK___FUNCTION__:
        if (!gnu_ext)
            goto tok_identifier;
        /* fall thru */
    case TOK___FUNC__:
        {
            void *ptr;
            int len;
            /* special function name identifier */
            len = strlen(funcname) + 1;
            /* generate char[len] type */
            type.t = VT_BYTE;
            mk_pointer(&type);
            type.t |= VT_ARRAY;
            type.ref->c = len;
            vpush_ref(&type, data_section, data_section->data_offset, len);
            ptr = section_ptr_add(data_section, len);
            memcpy(ptr, funcname, len);
            next();
        }
        break;
    case TOK_LSTR:
#ifdef TCC_TARGET_PE
        t = VT_SHORT | VT_UNSIGNED;
#else
        t = VT_INT;
#endif
        goto str_init;
    case TOK_STR:
        /* string parsing */
        t = VT_BYTE;
    str_init:
        if (tcc_state->warn_write_strings)
            t |= VT_CONSTANT;
        type.t = t;
        mk_pointer(&type);
        type.t |= VT_ARRAY;
        memset(&ad, 0, sizeof(AttributeDef));
        decl_initializer_alloc(&type, &ad, VT_CONST, 2, 0, 0);
        break;
    case '(':
        next();
        /* cast ? */
        if (parse_btype(&type, &ad)) {
            type_decl(&type, &ad, &n, TYPE_ABSTRACT);
            skip(')');
            /* check ISOC99 compound literal */
            if (tok == '{') {
                    /* data is allocated locally by default */
                if (global_expr)
                    r = VT_CONST;
                else
                    r = VT_LOCAL;
                /* all except arrays are lvalues */
                if (!(type.t & VT_ARRAY))
                    r |= lvalue_type(type.t);
                memset(&ad, 0, sizeof(AttributeDef));
                decl_initializer_alloc(&type, &ad, r, 1, 0, 0);
            } else {
                if (sizeof_caller) {
                    vpush(&type);
                    return;
                }
                unary();
                gen_cast(&type);
            }
        } else if (tok == '{') {
            if (const_wanted)
                tcc_error("expected constant");
            /* save all registers */
            if (!nocode_wanted)
                save_regs(0);
            /* statement expression : we do not accept break/continue
               inside as GCC does */
            block(NULL, NULL, NULL, NULL, 0, 1);
            skip(')');
        } else {
            gexpr();
            skip(')');
        }
        break;
    case '*':
        next();
        unary();
        indir();
        break;
    case '&':
        next();
        unary();
        /* functions names must be treated as function pointers,
           except for unary '&' and sizeof. Since we consider that
           functions are not lvalues, we only have to handle it
           there and in function calls. */
        /* arrays can also be used although they are not lvalues */
        if ((vtop->type.t & VT_BTYPE) != VT_FUNC &&
            !(vtop->type.t & VT_ARRAY) && !(vtop->type.t & VT_LLOCAL))
            test_lvalue();
        mk_pointer(&vtop->type);
        gaddrof();
        break;
    case '!':
        next();
        unary();
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            CType boolean;
            boolean.t = VT_BOOL;
            gen_cast(&boolean);
            vtop->c.i = !vtop->c.i;
        } else if ((vtop->r & VT_VALMASK) == VT_CMP)
            vtop->c.i ^= 1;
        else {
            save_regs(1);
            vseti(VT_JMP, gvtst(1, 0));
        }
        break;
    case '~':
        next();
        unary();
        vpushi(-1);
        gen_op('^');
        break;
    case '+':
        next();
        unary();
        if ((vtop->type.t & VT_BTYPE) == VT_PTR)
            tcc_error("pointer not accepted for unary plus");
        /* In order to force cast, we add zero, except for floating point
	   where we really need an noop (otherwise -0.0 will be transformed
	   into +0.0).  */
	if (!is_float(vtop->type.t)) {
	    vpushi(0);
	    gen_op('+');
	}
        break;
    case TOK_SIZEOF:
    case TOK_ALIGNOF1:
    case TOK_ALIGNOF2:
        t = tok;
        next();
        in_sizeof++;
        unary_type(&type); // Perform a in_sizeof = 0;
        size = type_size(&type, &align);
        if (t == TOK_SIZEOF) {
            if (!(type.t & VT_VLA)) {
                if (size < 0)
                    tcc_error("sizeof applied to an incomplete type");
                vpushs(size);
            } else {
                vla_runtime_type_size(&type, &align);
            }
        } else {
            vpushs(align);
        }
        vtop->type.t |= VT_UNSIGNED;
        break;

    case TOK_builtin_expect:
        {
            /* __builtin_expect is a no-op for now */
            int saved_nocode_wanted;
            next();
            skip('(');
            expr_eq();
            skip(',');
            saved_nocode_wanted = nocode_wanted;
            nocode_wanted = 1;
            expr_lor_const();
            vpop();
            nocode_wanted = saved_nocode_wanted;
            skip(')');
        }
        break;
    case TOK_builtin_types_compatible_p:
        {
            CType type1, type2;
            next();
            skip('(');
            parse_type(&type1);
            skip(',');
            parse_type(&type2);
            skip(')');
            type1.t &= ~(VT_CONSTANT | VT_VOLATILE);
            type2.t &= ~(VT_CONSTANT | VT_VOLATILE);
            vpushi(is_compatible_types(&type1, &type2));
        }
        break;
    case TOK_builtin_constant_p:
        {
            int saved_nocode_wanted, res;
            next();
            skip('(');
            saved_nocode_wanted = nocode_wanted;
            nocode_wanted = 1;
            gexpr();
            res = (vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
            vpop();
            nocode_wanted = saved_nocode_wanted;
            skip(')');
            vpushi(res);
        }
        break;
    case TOK_builtin_frame_address:
    case TOK_builtin_return_address:
        {
            int tok1 = tok;
            int level;
            CType type;
            next();
            skip('(');
            if (tok != TOK_CINT) {
                tcc_error("%s only takes positive integers",
                          tok1 == TOK_builtin_return_address ?
                          "__builtin_return_address" :
                          "__builtin_frame_address");
            }
            level = (uint32_t)tokc.i;
            next();
            skip(')');
            type.t = VT_VOID;
            mk_pointer(&type);
            vset(&type, VT_LOCAL, 0);       /* local frame */
            while (level--) {
                mk_pointer(&vtop->type);
                indir();                    /* -> parent frame */
            }
            if (tok1 == TOK_builtin_return_address) {
                // assume return address is just above frame pointer on stack
                vpushi(PTR_SIZE);
                gen_op('+');
                mk_pointer(&vtop->type);
                indir();
            }
        }
        break;
#ifdef TCC_TARGET_X86_64
#ifdef TCC_TARGET_PE
    case TOK_builtin_va_start:
        {
            next();
            skip('(');
            expr_eq();
            skip(',');
            expr_eq();
            skip(')');
            if ((vtop->r & VT_VALMASK) != VT_LOCAL)
                tcc_error("__builtin_va_start expects a local variable");
            vtop->r &= ~(VT_LVAL | VT_REF);
            vtop->type = char_pointer_type;
            vtop->c.i += 8;
            vstore();
        }
        break;
#else
    case TOK_builtin_va_arg_types:
        {
            CType type;
            next();
            skip('(');
            parse_type(&type);
            skip(')');
            vpushi(classify_x86_64_va_arg(&type));
        }
        break;
#endif
#endif

#ifdef TCC_TARGET_ARM64
    case TOK___va_start: {
        if (nocode_wanted)
            tcc_error("statement in global scope");
        next();
        skip('(');
        expr_eq();
        skip(',');
        expr_eq();
        skip(')');
        //xx check types
        gen_va_start();
        vpushi(0);
        vtop->type.t = VT_VOID;
        break;
    }
    case TOK___va_arg: {
        CType type;
        if (nocode_wanted)
            tcc_error("statement in global scope");
        next();
        skip('(');
        expr_eq();
        skip(',');
        parse_type(&type);
        skip(')');
        //xx check types
        gen_va_arg(&type);
        vtop->type = type;
        break;
    }
    case TOK___arm64_clear_cache: {
        next();
        skip('(');
        expr_eq();
        skip(',');
        expr_eq();
        skip(')');
        gen_clear_cache();
        vpushi(0);
        vtop->type.t = VT_VOID;
        break;
    }
#endif
    /* pre operations */
    case TOK_INC:
    case TOK_DEC:
        t = tok;
        next();
        unary();
        inc(0, t);
        break;
    case '-':
        next();
        unary();
        t = vtop->type.t & VT_BTYPE;
	if (is_float(t)) {
            /* In IEEE negate(x) isn't subtract(0,x), but rather
	       subtract(-0, x).  */
	    vpush(&vtop->type);
	    if (t == VT_FLOAT)
	        vtop->c.f = -0.0f;
	    else if (t == VT_DOUBLE)
	        vtop->c.d = -0.0;
	    else
	        vtop->c.ld = -0.0;
	} else
	    vpushi(0);
	vswap();
	gen_op('-');
        break;
    case TOK_LAND:
        if (!gnu_ext)
            goto tok_identifier;
        next();
        /* allow to take the address of a label */
        if (tok < TOK_UIDENT)
            expect("label identifier");
        s = label_find(tok);
        if (!s) {
            s = label_push(&global_label_stack, tok, LABEL_FORWARD);
        } else {
            if (s->r == LABEL_DECLARED)
                s->r = LABEL_FORWARD;
        }
        if (!s->type.t) {
            s->type.t = VT_VOID;
            mk_pointer(&s->type);
            s->type.t |= VT_STATIC;
        }
        vpushsym(&s->type, s);
        next();
        break;
    
    // special qnan , snan and infinity values
    case TOK___NAN__:
        vpush64(VT_DOUBLE, 0x7ff8000000000000ULL);
        next();
        break;
    case TOK___SNAN__:
        vpush64(VT_DOUBLE, 0x7ff0000000000001ULL);
        next();
        break;
    case TOK___INF__:
        vpush64(VT_DOUBLE, 0x7ff0000000000000ULL);
        next();
        break;

    default:
    tok_identifier:
        t = tok;
        next();
        if (t < TOK_UIDENT)
            expect("identifier");
        s = sym_find(t);
        if (!s) {
            const char *name = get_tok_str(t, NULL);
            if (tok != '(')
                tcc_error("'%s' undeclared", name);
            /* for simple function calls, we tolerate undeclared
               external reference to int() function */
            if (tcc_state->warn_implicit_function_declaration
#ifdef TCC_TARGET_PE
                /* people must be warned about using undeclared WINAPI functions
                   (which usually start with uppercase letter) */
                || (name[0] >= 'A' && name[0] <= 'Z')
#endif
            )
                tcc_warning("implicit declaration of function '%s'", name);
            s = external_global_sym(t, &func_old_type, 0); 
        }
        if ((s->type.t & (VT_STATIC | VT_INLINE | VT_BTYPE)) ==
            (VT_STATIC | VT_INLINE | VT_FUNC)) {
            /* if referencing an inline function, then we generate a
               symbol to it if not already done. It will have the
               effect to generate code for it at the end of the
               compilation unit. Inline function as always
               generated in the text section. */
            if (!s->c)
                put_extern_sym(s, text_section, 0, 0);
            r = VT_SYM | VT_CONST;
        } else {
            r = s->r;
        }
        vset(&s->type, r, s->c);
        /* if forward reference, we must point to s */
        if (vtop->r & VT_SYM) {
            vtop->sym = s;
            vtop->c.i = 0;
        }
        break;
    }
    
    /* post operations */
    while (1) {
        if (tok == TOK_INC || tok == TOK_DEC) {
            inc(1, tok);
            next();
        } else if (tok == '.' || tok == TOK_ARROW || tok == TOK_CDOUBLE) {
            int qualifiers;
            /* field */ 
            if (tok == TOK_ARROW) 
                indir();
            qualifiers = vtop->type.t & (VT_CONSTANT | VT_VOLATILE);
            test_lvalue();
            gaddrof();
            /* expect pointer on structure */
            if ((vtop->type.t & VT_BTYPE) != VT_STRUCT)
                expect("struct or union");
            if (tok == TOK_CDOUBLE)
                expect("field name");
            next();
            if (tok == TOK_CINT || tok == TOK_CUINT)
                expect("field name");
            s = vtop->type.ref;
            /* find field */
            tok |= SYM_FIELD;
            while ((s = s->next) != NULL) {
                if (s->v == tok)
                    break;
            }
            if (!s)
                tcc_error("field not found: %s",  get_tok_str(tok & ~SYM_FIELD, &tokc));
            /* add field offset to pointer */
            vtop->type = char_pointer_type; /* change type to 'char *' */
            vpushi(s->c);
            gen_op('+');
            /* change type to field type, and set to lvalue */
            vtop->type = s->type;
            vtop->type.t |= qualifiers;
            /* an array is never an lvalue */
            if (!(vtop->type.t & VT_ARRAY)) {
                vtop->r |= lvalue_type(vtop->type.t);
#ifdef CONFIG_TCC_BCHECK
                /* if bound checking, the referenced pointer must be checked */
                if (tcc_state->do_bounds_check)
                    vtop->r |= VT_MUSTBOUND;
#endif
            }
            next();
        } else if (tok == '[') {
            next();
            gexpr();
            gen_op('+');
            indir();
            skip(']');
        } else if (tok == '(') {
            SValue ret;
            Sym *sa;
            int nb_args, ret_nregs, ret_align, regsize, variadic;

            /* function call  */
            if ((vtop->type.t & VT_BTYPE) != VT_FUNC) {
                /* pointer test (no array accepted) */
                if ((vtop->type.t & (VT_BTYPE | VT_ARRAY)) == VT_PTR) {
                    vtop->type = *pointed_type(&vtop->type);
                    if ((vtop->type.t & VT_BTYPE) != VT_FUNC)
                        goto error_func;
                } else {
                error_func:
                    expect("function pointer");
                }
            } else {
                vtop->r &= ~VT_LVAL; /* no lvalue */
            }
            /* get return type */
            s = vtop->type.ref;
            next();
            sa = s->next; /* first parameter */
            nb_args = 0;
            ret.r2 = VT_CONST;
            /* compute first implicit argument if a structure is returned */
            if ((s->type.t & VT_BTYPE) == VT_STRUCT) {
                variadic = (s->c == FUNC_ELLIPSIS);
                ret_nregs = gfunc_sret(&s->type, variadic, &ret.type,
                                       &ret_align, &regsize);
                if (!ret_nregs) {
                    /* get some space for the returned structure */
                    size = type_size(&s->type, &align);
#ifdef TCC_TARGET_ARM64
                /* On arm64, a small struct is return in registers.
                   It is much easier to write it to memory if we know
                   that we are allowed to write some extra bytes, so
                   round the allocated space up to a power of 2: */
                if (size < 16)
                    while (size & (size - 1))
                        size = (size | (size - 1)) + 1;
#endif
                    loc = (loc - size) & -align;
                    ret.type = s->type;
                    ret.r = VT_LOCAL | VT_LVAL;
                    /* pass it as 'int' to avoid structure arg passing
                       problems */
                    vseti(VT_LOCAL, loc);
                    ret.c = vtop->c;
                    nb_args++;
                }
            } else {
                ret_nregs = 1;
                ret.type = s->type;
            }

            if (ret_nregs) {
                /* return in register */
                if (is_float(ret.type.t)) {
                    ret.r = reg_fret(ret.type.t);
#ifdef TCC_TARGET_X86_64
                    if ((ret.type.t & VT_BTYPE) == VT_QFLOAT)
                      ret.r2 = REG_QRET;
#endif
                } else {
#ifndef TCC_TARGET_ARM64
#ifdef TCC_TARGET_X86_64
                    if ((ret.type.t & VT_BTYPE) == VT_QLONG)
#else
                    if ((ret.type.t & VT_BTYPE) == VT_LLONG)
#endif
                        ret.r2 = REG_LRET;
#endif
                    ret.r = REG_IRET;
                }
                ret.c.i = 0;
            }
            if (tok != ')') {
                for(;;) {
                    expr_eq();
                    gfunc_param_typed(s, sa);
                    nb_args++;
                    if (sa)
                        sa = sa->next;
                    if (tok == ')')
                        break;
                    skip(',');
                }
            }
            if (sa)
                tcc_error("too few arguments to function");
            skip(')');
            if (!nocode_wanted) {
                gfunc_call(nb_args);
            } else {
                vtop -= (nb_args + 1);
            }

            /* return value */
            for (r = ret.r + ret_nregs + !ret_nregs; r-- > ret.r;) {
                vsetc(&ret.type, r, &ret.c);
                vtop->r2 = ret.r2; /* Loop only happens when r2 is VT_CONST */
            }

            /* handle packed struct return */
            if (((s->type.t & VT_BTYPE) == VT_STRUCT) && ret_nregs) {
                int addr, offset;

                size = type_size(&s->type, &align);
		/* We're writing whole regs often, make sure there's enough
		   space.  Assume register size is power of 2.  */
		if (regsize > align)
		  align = regsize;
                loc = (loc - size) & -align;
                addr = loc;
                offset = 0;
                for (;;) {
                    vset(&ret.type, VT_LOCAL | VT_LVAL, addr + offset);
                    vswap();
                    vstore();
                    vtop--;
                    if (--ret_nregs == 0)
                        break;
                    offset += regsize;
                }
                vset(&s->type, VT_LOCAL | VT_LVAL, addr);
            }
        } else {
            break;
        }
    }
}

ST_FUNC void expr_prod(void)
{
    int t;

    unary();
    while (tok == '*' || tok == '/' || tok == '%') {
        t = tok;
        next();
        unary();
        gen_op(t);
    }
}

ST_FUNC void expr_sum(void)
{
    int t;

    expr_prod();
    while (tok == '+' || tok == '-') {
        t = tok;
        next();
        expr_prod();
        gen_op(t);
    }
}

static void expr_shift(void)
{
    int t;

    expr_sum();
    while (tok == TOK_SHL || tok == TOK_SAR) {
        t = tok;
        next();
        expr_sum();
        gen_op(t);
    }
}

static void expr_cmp(void)
{
    int t;

    expr_shift();
    while ((tok >= TOK_ULE && tok <= TOK_GT) ||
           tok == TOK_ULT || tok == TOK_UGE) {
        t = tok;
        next();
        expr_shift();
        gen_op(t);
    }
}

static void expr_cmpeq(void)
{
    int t;

    expr_cmp();
    while (tok == TOK_EQ || tok == TOK_NE) {
        t = tok;
        next();
        expr_cmp();
        gen_op(t);
    }
}

static void expr_and(void)
{
    expr_cmpeq();
    while (tok == '&') {
        next();
        expr_cmpeq();
        gen_op('&');
    }
}

static void expr_xor(void)
{
    expr_and();
    while (tok == '^') {
        next();
        expr_and();
        gen_op('^');
    }
}

static void expr_or(void)
{
    expr_xor();
    while (tok == '|') {
        next();
        expr_xor();
        gen_op('|');
    }
}

/* XXX: fix this mess */
static void expr_land_const(void)
{
    expr_or();
    while (tok == TOK_LAND) {
        next();
        expr_or();
        gen_op(TOK_LAND);
    }
}
static void expr_lor_const(void)
{
    expr_land_const();
    while (tok == TOK_LOR) {
        next();
        expr_land_const();
        gen_op(TOK_LOR);
    }
}

static void expr_land(void)
{
    expr_or();
    if (tok == TOK_LAND) {
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            CType ctb, cti;
            ctb.t = VT_BOOL;
            cti.t = VT_INT;
            next();
            gen_cast(&ctb);
            if (vtop->c.i) {
                vpop();
                expr_land();
                gen_cast(&ctb);
            } else {
                int saved_nocode_wanted = nocode_wanted;
                nocode_wanted = 1;
                expr_land();
                vpop();
                nocode_wanted = saved_nocode_wanted;
            }
            gen_cast(&cti);
        } else {
            int t = 0;
            save_regs(1);
            for(;;) {
                t = gvtst(1, t);
                if (tok != TOK_LAND) {
                    vseti(VT_JMPI, t);
                    break;
                }
                next();
                expr_or();
            }
        }
    }
}

static void expr_lor(void)
{
    expr_land();
    if (tok == TOK_LOR) {
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            CType ctb, cti;
            ctb.t = VT_BOOL;
            cti.t = VT_INT;
            next();
            gen_cast(&ctb);
            if (vtop->c.i) {
                int saved_nocode_wanted = nocode_wanted;
                nocode_wanted = 1;
                expr_lor();
                vpop();
                nocode_wanted = saved_nocode_wanted;
            } else {
                vpop();
                expr_lor();
                gen_cast(&ctb);
            }
            gen_cast(&cti);
        } else {
            int t = 0;
            save_regs(1);
            for(;;) {
                t = gvtst(0, t);
                if (tok != TOK_LOR) {
                    vseti(VT_JMP, t);
                    break;
                }
                next();
                expr_land();
            }
        }
    }
}

static void expr_cond(void)
{
    int tt, u, r1, r2, rc, t1, t2, bt1, bt2, islv;
    SValue sv;
    CType type, type1, type2;

    expr_lor();
    if (tok == '?') {
        next();
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            int saved_nocode_wanted = nocode_wanted;
            CType boolean;
            int c;
            boolean.t = VT_BOOL;
            vdup();
            gen_cast(&boolean);
            c = vtop->c.i;
            vpop();
            if (c) {
                if (tok != ':' || !gnu_ext) {
                    vpop();
                    gexpr();
                }
                skip(':');
                nocode_wanted = 1;
                expr_cond();
                vpop();
                nocode_wanted = saved_nocode_wanted;
            } else {
                vpop();
                if (tok != ':' || !gnu_ext) {
                    nocode_wanted = 1;
                    gexpr();
                    vpop();
                    nocode_wanted = saved_nocode_wanted;
                }
                skip(':');
                expr_cond();
            }
        }
        else {
            if (vtop != vstack) {
                /* needed to avoid having different registers saved in
                   each branch */
                if (is_float(vtop->type.t)) {
                    rc = RC_FLOAT;
#ifdef TCC_TARGET_X86_64
                    if ((vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
                        rc = RC_ST0;
                    }
#endif
                }
                else
                    rc = RC_INT;
                    gv(rc);
                    save_regs(1);
            }
            if (tok == ':' && gnu_ext) {
                gv_dup();
                tt = gvtst(1, 0);
            } else {
                tt = gvtst(1, 0);
                gexpr();
            }
            type1 = vtop->type;
            sv = *vtop; /* save value to handle it later */
            vtop--; /* no vpop so that FP stack is not flushed */
            skip(':');
            u = gjmp(0);
            gsym(tt);
            expr_cond();
            type2 = vtop->type;

            t1 = type1.t;
            bt1 = t1 & VT_BTYPE;
            t2 = type2.t;
            bt2 = t2 & VT_BTYPE;
            /* cast operands to correct type according to ISOC rules */
            if (is_float(bt1) || is_float(bt2)) {
                if (bt1 == VT_LDOUBLE || bt2 == VT_LDOUBLE) {
                    type.t = VT_LDOUBLE;
                } else if (bt1 == VT_DOUBLE || bt2 == VT_DOUBLE) {
                    type.t = VT_DOUBLE;
                } else {
                    type.t = VT_FLOAT;
                }
            } else if (bt1 == VT_LLONG || bt2 == VT_LLONG) {
                /* cast to biggest op */
                type.t = VT_LLONG;
                /* convert to unsigned if it does not fit in a long long */
                if ((t1 & (VT_BTYPE | VT_UNSIGNED)) == (VT_LLONG | VT_UNSIGNED) ||
                    (t2 & (VT_BTYPE | VT_UNSIGNED)) == (VT_LLONG | VT_UNSIGNED))
                    type.t |= VT_UNSIGNED;
            } else if (bt1 == VT_PTR || bt2 == VT_PTR) {
		/* If one is a null ptr constant the result type
		   is the other.  */
		if (is_null_pointer (vtop))
		  type = type1;
		else if (is_null_pointer (&sv))
		  type = type2;
                /* XXX: test pointer compatibility, C99 has more elaborate
		   rules here.  */
		else
		  type = type1;
            } else if (bt1 == VT_FUNC || bt2 == VT_FUNC) {
                /* XXX: test function pointer compatibility */
                type = bt1 == VT_FUNC ? type1 : type2;
            } else if (bt1 == VT_STRUCT || bt2 == VT_STRUCT) {
                /* XXX: test structure compatibility */
                type = bt1 == VT_STRUCT ? type1 : type2;
            } else if (bt1 == VT_VOID || bt2 == VT_VOID) {
                /* NOTE: as an extension, we accept void on only one side */
                type.t = VT_VOID;
            } else {
                /* integer operations */
                type.t = VT_INT;
                /* convert to unsigned if it does not fit in an integer */
                if ((t1 & (VT_BTYPE | VT_UNSIGNED)) == (VT_INT | VT_UNSIGNED) ||
                    (t2 & (VT_BTYPE | VT_UNSIGNED)) == (VT_INT | VT_UNSIGNED))
                    type.t |= VT_UNSIGNED;
            }
            /* keep structs lvalue by transforming `(expr ? a : b)` to `*(expr ? &a : &b)` so
               that `(expr ? a : b).mem` does not error  with "lvalue expected" */
            islv = (vtop->r & VT_LVAL) && (sv.r & VT_LVAL) && VT_STRUCT == (type.t & VT_BTYPE);

            /* now we convert second operand */
            gen_cast(&type);
            if (islv) {
                mk_pointer(&vtop->type);
                gaddrof();
            }
            else if (VT_STRUCT == (vtop->type.t & VT_BTYPE))
                gaddrof();
            rc = RC_INT;
            if (is_float(type.t)) {
                rc = RC_FLOAT;
#ifdef TCC_TARGET_X86_64
                if ((type.t & VT_BTYPE) == VT_LDOUBLE) {
                    rc = RC_ST0;
                }
#endif
            } else if ((type.t & VT_BTYPE) == VT_LLONG) {
                /* for long longs, we use fixed registers to avoid having
                   to handle a complicated move */
                rc = RC_IRET; 
            }
            
            r2 = gv(rc);
            /* this is horrible, but we must also convert first
               operand */
            tt = gjmp(0);
            gsym(u);
            /* put again first value and cast it */
            *vtop = sv;
            gen_cast(&type);
            if (islv) {
                mk_pointer(&vtop->type);
                gaddrof();
            }
            else if (VT_STRUCT == (vtop->type.t & VT_BTYPE))
                gaddrof();
            r1 = gv(rc);
            move_reg(r2, r1, type.t);
            vtop->r = r2;
            gsym(tt);
            if (islv)
                indir();
        }
    }
}

static void expr_eq(void)
{
    int t;
    
    expr_cond();
    if (tok == '=' ||
        (tok >= TOK_A_MOD && tok <= TOK_A_DIV) ||
        tok == TOK_A_XOR || tok == TOK_A_OR ||
        tok == TOK_A_SHL || tok == TOK_A_SAR) {
        test_lvalue();
        t = tok;
        next();
        if (t == '=') {
            expr_eq();
        } else {
            vdup();
            expr_eq();
            gen_op(t & 0x7f);
        }
        vstore();
    }
}

ST_FUNC void gexpr(void)
{
    while (1) {
        expr_eq();
        if (tok != ',')
            break;
        vpop();
        next();
    }
}

/* parse an expression and return its type without any side effect. */
static void expr_type(CType *type)
{
    int saved_nocode_wanted;

    saved_nocode_wanted = nocode_wanted;
    nocode_wanted = 1;
    gexpr();
    *type = vtop->type;
    vpop();
    nocode_wanted = saved_nocode_wanted;
}

/* parse a unary expression and return its type without any side
   effect. */
static void unary_type(CType *type)
{
    int a;

    a = nocode_wanted;
    nocode_wanted = 1;
    unary();
    *type = vtop->type;
    vpop();
    nocode_wanted = a;
}

/* parse a constant expression and return value in vtop.  */
static void expr_const1(void)
{
    int a;
    a = const_wanted;
    const_wanted = 1;
    expr_cond();
    const_wanted = a;
}

/* parse an integer constant and return its value. */
ST_FUNC int expr_const(void)
{
    int c;
    expr_const1();
    if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) != VT_CONST)
        expect("constant expression");
    c = vtop->c.i;
    vpop();
    return c;
}

/* return the label token if current token is a label, otherwise
   return zero */
static int is_label(void)
{
    int last_tok;

    /* fast test first */
    if (tok < TOK_UIDENT)
        return 0;
    /* no need to save tokc because tok is an identifier */
    last_tok = tok;
    next();
    if (tok == ':') {
        next();
        return last_tok;
    } else {
        unget_tok(last_tok);
        return 0;
    }
}

static void label_or_decl(int l)
{
    int last_tok;

    /* fast test first */
    if (tok >= TOK_UIDENT)
      {
	/* no need to save tokc because tok is an identifier */
	last_tok = tok;
	next();
	if (tok == ':') {
	    unget_tok(last_tok);
	    return;
	}
	unget_tok(last_tok);
      }
    decl(l);
}

static void block(int *bsym, int *csym, int *case_sym, int *def_sym, 
                  int case_reg, int is_expr)
{
    int a, b, c, d;
    Sym *s;

    /* generate line number info */
    if (tcc_state->do_debug &&
        (last_line_num != file->line_num || last_ind != ind)) {
        put_stabn(N_SLINE, 0, file->line_num, ind - func_ind);
        last_ind = ind;
        last_line_num = file->line_num;
    }

    if (is_expr) {
        /* default return value is (void) */
        vpushi(0);
        vtop->type.t = VT_VOID;
    }

    if (tok == TOK_IF) {
        /* if test */
        next();
        skip('(');
        gexpr();
        skip(')');
        a = gvtst(1, 0);
        block(bsym, csym, case_sym, def_sym, case_reg, 0);
        c = tok;
        if (c == TOK_ELSE) {
            next();
            d = gjmp(0);
            gsym(a);
            block(bsym, csym, case_sym, def_sym, case_reg, 0);
            gsym(d); /* patch else jmp */
        } else
            gsym(a);
    } else if (tok == TOK_WHILE) {
        next();
        d = ind;
        vla_sp_restore();
        skip('(');
        gexpr();
        skip(')');
        a = gvtst(1, 0);
        b = 0;
        ++local_scope;
        block(&a, &b, case_sym, def_sym, case_reg, 0);
        --local_scope;
        if(!nocode_wanted)
            gjmp_addr(d);
        gsym(a);
        gsym_addr(b, d);
    } else if (tok == '{') {
        Sym *llabel;
        int block_vla_sp_loc = vla_sp_loc, saved_vlas_in_scope = vlas_in_scope;

        next();
        /* record local declaration stack position */
        s = local_stack;
        llabel = local_label_stack;
        ++local_scope;
        
        /* handle local labels declarations */
        if (tok == TOK_LABEL) {
            next();
            for(;;) {
                if (tok < TOK_UIDENT)
                    expect("label identifier");
                label_push(&local_label_stack, tok, LABEL_DECLARED);
                next();
                if (tok == ',') {
                    next();
                } else {
                    skip(';');
                    break;
                }
            }
        }
        while (tok != '}') {
            label_or_decl(VT_LOCAL);
            if (tok != '}') {
                if (is_expr)
                    vpop();
                block(bsym, csym, case_sym, def_sym, case_reg, is_expr);
            }
        }
        /* pop locally defined labels */
        label_pop(&local_label_stack, llabel);
        if(is_expr) {
            /* XXX: this solution makes only valgrind happy...
               triggered by gcc.c-torture/execute/20000917-1.c */
            Sym *p;
            switch(vtop->type.t & VT_BTYPE) {
            /* case VT_PTR: */
        	/* this breaks a compilation of the linux kernel v2.4.26 */
        	/* pmd_t *new = ({ __asm__ __volatile__("ud2\n") ; ((pmd_t *)1); }); */
        	/* Look a commit a80acab: Display error on statement expressions with complex return type */
        	/* A pointer is not a complex return type */
            case VT_STRUCT:
            case VT_ENUM:
            case VT_FUNC:
                for(p=vtop->type.ref;p;p=p->prev)
                    if(p->prev==s)
                        tcc_error("unsupported expression type");
            }
        }
        /* pop locally defined symbols */
        --local_scope;
        sym_pop(&local_stack, s);
        
        /* Pop VLA frames and restore stack pointer if required */
        if (vlas_in_scope > saved_vlas_in_scope) {
            vla_sp_loc = saved_vlas_in_scope ? block_vla_sp_loc : vla_sp_root_loc;
            vla_sp_restore();
        }
        vlas_in_scope = saved_vlas_in_scope;
        
        next();
    } else if (tok == TOK_RETURN) {
        next();
        if (tok != ';') {
            gexpr();
            gen_assign_cast(&func_vt);
#ifdef TCC_TARGET_ARM64
            // Perhaps it would be better to use this for all backends:
            greturn();
#else
            if ((func_vt.t & VT_BTYPE) == VT_STRUCT) {
                CType type, ret_type;
                int ret_align, ret_nregs, regsize;
                ret_nregs = gfunc_sret(&func_vt, func_var, &ret_type,
                                       &ret_align, &regsize);
                if (0 == ret_nregs) {
                    /* if returning structure, must copy it to implicit
                       first pointer arg location */
                    type = func_vt;
                    mk_pointer(&type);
                    vset(&type, VT_LOCAL | VT_LVAL, func_vc);
                    indir();
                    vswap();
                    /* copy structure value to pointer */
                    vstore();
                } else {
                    /* returning structure packed into registers */
                    int r, size, addr, align;
                    size = type_size(&func_vt,&align);
                    if ((vtop->r != (VT_LOCAL | VT_LVAL) ||
                         (vtop->c.i & (ret_align-1)))
                        && (align & (ret_align-1))) {
                        loc = (loc - size) & -ret_align;
                        addr = loc;
                        type = func_vt;
                        vset(&type, VT_LOCAL | VT_LVAL, addr);
                        vswap();
                        vstore();
                        vpop();
                        vset(&ret_type, VT_LOCAL | VT_LVAL, addr);
                    }
                    vtop->type = ret_type;
                    if (is_float(ret_type.t))
                        r = rc_fret(ret_type.t);
                    else
                        r = RC_IRET;

                    for (;;) {
                        gv(r);
                        if (--ret_nregs == 0)
                            break;
                        /* We assume that when a structure is returned in multiple
                           registers, their classes are consecutive values of the
                           suite s(n) = 2^n */
                        r <<= 1;
                        vtop->c.i += regsize;
                        vtop->r = VT_LOCAL | VT_LVAL;
                    }
                }
            } else if (is_float(func_vt.t)) {
                gv(rc_fret(func_vt.t));
            } else {
                gv(RC_IRET);
            }
#endif
            vtop--; /* NOT vpop() because on x86 it would flush the fp stack */
        }
        skip(';');
        /* jump unless last stmt in top-level block */
        if (tok != '}' || local_scope != 1)
            rsym = gjmp(rsym);
    } else if (tok == TOK_BREAK) {
        /* compute jump */
        if (!bsym)
            tcc_error("cannot break");
        *bsym = gjmp(*bsym);
        next();
        skip(';');
    } else if (tok == TOK_CONTINUE) {
        /* compute jump */
        if (!csym)
            tcc_error("cannot continue");
        vla_sp_restore_root();
        *csym = gjmp(*csym);
        next();
        skip(';');
    } else if (tok == TOK_FOR) {
        int e;
        next();
        skip('(');
        s = local_stack;
        ++local_scope;
        if (tok != ';') {
            /* c99 for-loop init decl? */
            if (!decl0(VT_LOCAL, 1)) {
                /* no, regular for-loop init expr */
                gexpr();
                vpop();
            }
        }
        skip(';');
        d = ind;
        c = ind;
        vla_sp_restore();
        a = 0;
        b = 0;
        if (tok != ';') {
            gexpr();
            a = gvtst(1, 0);
        }
        skip(';');
        if (tok != ')') {
            e = gjmp(0);
            c = ind;
            vla_sp_restore();
            gexpr();
            vpop();
            gjmp_addr(d);
            gsym(e);
        }
        skip(')');
        block(&a, &b, case_sym, def_sym, case_reg, 0);
        if(!nocode_wanted)
            gjmp_addr(c);
        gsym(a);
        gsym_addr(b, c);
        --local_scope;
        sym_pop(&local_stack, s);

    } else 
    if (tok == TOK_DO) {
        next();
        a = 0;
        b = 0;
        d = ind;
        vla_sp_restore();
        block(&a, &b, case_sym, def_sym, case_reg, 0);
        skip(TOK_WHILE);
        skip('(');
        gsym(b);
        gexpr();
        c = gvtst(0, 0);
        gsym_addr(c, d);
        skip(')');
        gsym(a);
        skip(';');
    } else
    if (tok == TOK_SWITCH) {
        next();
        skip('(');
        gexpr();
        /* XXX: other types than integer */
        case_reg = gv(RC_INT);
        vpop();
        skip(')');
        a = 0;
        b = gjmp(0); /* jump to first case */
        c = 0;
        block(&a, csym, &b, &c, case_reg, 0);
        /* if no default, jmp after switch */
        if (c == 0)
            c = ind;
        /* default label */
        gsym_addr(b, c);
        /* break label */
        gsym(a);
    } else
    if (tok == TOK_CASE) {
        int v1, v2;
        if (!case_sym)
            expect("switch");
        next();
        v1 = expr_const();
        v2 = v1;
        if (gnu_ext && tok == TOK_DOTS) {
            next();
            v2 = expr_const();
            if (v2 < v1)
                tcc_warning("empty case range");
        }
        /* since a case is like a label, we must skip it with a jmp */
        b = gjmp(0);
        gsym(*case_sym);
        vseti(case_reg, 0);
        vdup();
        vpushi(v1);
        if (v1 == v2) {
            gen_op(TOK_EQ);
            *case_sym = gtst(1, 0);
        } else {
            gen_op(TOK_GE);
            *case_sym = gtst(1, 0);
            vseti(case_reg, 0);
            vpushi(v2);
            gen_op(TOK_LE);
            *case_sym = gtst(1, *case_sym);
        }
        case_reg = gv(RC_INT);
        vpop();
        gsym(b);
        skip(':');
        is_expr = 0;
        goto block_after_label;
    } else 
    if (tok == TOK_DEFAULT) {
        next();
        skip(':');
        if (!def_sym)
            expect("switch");
        if (*def_sym)
            tcc_error("too many 'default'");
        *def_sym = ind;
        is_expr = 0;
        goto block_after_label;
    } else
    if (tok == TOK_GOTO) {
        next();
        if (tok == '*' && gnu_ext) {
            /* computed goto */
            next();
            gexpr();
            if ((vtop->type.t & VT_BTYPE) != VT_PTR)
                expect("pointer");
            ggoto();
        } else if (tok >= TOK_UIDENT) {
            s = label_find(tok);
            /* put forward definition if needed */
            if (!s) {
                s = label_push(&global_label_stack, tok, LABEL_FORWARD);
            } else {
                if (s->r == LABEL_DECLARED)
                    s->r = LABEL_FORWARD;
            }
            vla_sp_restore_root();
            if (s->r & LABEL_FORWARD) 
                s->jnext = gjmp(s->jnext);
            else
                gjmp_addr(s->jnext);
            next();
        } else {
            expect("label identifier");
        }
        skip(';');
    } else if (tok == TOK_ASM1 || tok == TOK_ASM2 || tok == TOK_ASM3) {
        asm_instr();
    } else {
        b = is_label();
        if (b) {
            /* label case */
            s = label_find(b);
            if (s) {
                if (s->r == LABEL_DEFINED)
                    tcc_error("duplicate label '%s'", get_tok_str(s->v, NULL));
                gsym(s->jnext);
                s->r = LABEL_DEFINED;
            } else {
                s = label_push(&global_label_stack, b, LABEL_DEFINED);
            }
            s->jnext = ind;
            vla_sp_restore();
            /* we accept this, but it is a mistake */
        block_after_label:
            if (tok == '}') {
                tcc_warning("deprecated use of label at end of compound statement");
            } else {
                if (is_expr)
                    vpop();
                block(bsym, csym, case_sym, def_sym, case_reg, is_expr);
            }
        } else {
            /* expression case */
            if (tok != ';') {
                if (is_expr) {
                    vpop();
                    gexpr();
                } else {
                    gexpr();
                    vpop();
                }
            }
            skip(';');
        }
    }
}

/* t is the array or struct type. c is the array or struct
   address. cur_index/cur_field is the pointer to the current
   value. 'size_only' is true if only size info is needed (only used
   in arrays) */
static void decl_designator(CType *type, Section *sec, unsigned long c, 
                            int *cur_index, Sym **cur_field, 
                            int size_only)
{
    Sym *s, *f;
    int notfirst, index, index_last, align, l, nb_elems, elem_size;
    CType type1;

    notfirst = 0;
    elem_size = 0;
    nb_elems = 1;
    if (gnu_ext && (l = is_label()) != 0)
        goto struct_field;
    while (tok == '[' || tok == '.') {
        if (tok == '[') {
            if (!(type->t & VT_ARRAY))
                expect("array type");
            s = type->ref;
            next();
            index = expr_const();
            if (index < 0 || (s->c >= 0 && index >= s->c))
                expect("invalid index");
            if (tok == TOK_DOTS && gnu_ext) {
                next();
                index_last = expr_const();
                if (index_last < 0 || 
                    (s->c >= 0 && index_last >= s->c) ||
                    index_last < index)
                    expect("invalid index");
            } else {
                index_last = index;
            }
            skip(']');
            if (!notfirst)
                *cur_index = index_last;
            type = pointed_type(type);
            elem_size = type_size(type, &align);
            c += index * elem_size;
            /* NOTE: we only support ranges for last designator */
            nb_elems = index_last - index + 1;
            if (nb_elems != 1) {
                notfirst = 1;
                break;
            }
        } else {
            next();
            l = tok;
            next();
        struct_field:
            if ((type->t & VT_BTYPE) != VT_STRUCT)
                expect("struct/union type");
            s = type->ref;
            l |= SYM_FIELD;
            f = s->next;
            while (f) {
                if (f->v == l)
                    break;
                f = f->next;
            }
            if (!f)
                expect("field");
            if (!notfirst)
                *cur_field = f;
            /* XXX: fix this mess by using explicit storage field */
            type1 = f->type;
            type1.t |= (type->t & ~VT_TYPE);
            type = &type1;
            c += f->c;
        }
        notfirst = 1;
    }
    if (notfirst) {
        if (tok == '=') {
            next();
        } else {
            if (!gnu_ext)
                expect("=");
        }
    } else {
        if (type->t & VT_ARRAY) {
            index = *cur_index;
            type = pointed_type(type);
            c += index * type_size(type, &align);
        } else {
            f = *cur_field;
            if (!f)
                tcc_error("too many field init");
            /* XXX: fix this mess by using explicit storage field */
            type1 = f->type;
            type1.t |= (type->t & ~VT_TYPE);
            type = &type1;
            c += f->c;
        }
    }
    decl_initializer(type, sec, c, 0, size_only);

    /* XXX: make it more general */
    if (!size_only && nb_elems > 1) {
        unsigned long c_end;
        uint8_t *src, *dst;
        int i;

        if (!sec)
            tcc_error("range init not supported yet for dynamic storage");
        c_end = c + nb_elems * elem_size;
        if (c_end > sec->data_allocated)
            section_realloc(sec, c_end);
        src = sec->data + c;
        dst = src;
        for(i = 1; i < nb_elems; i++) {
            dst += elem_size;
            memcpy(dst, src, elem_size);
        }
    }
}

#define EXPR_VAL   0
#define EXPR_CONST 1
#define EXPR_ANY   2

/* store a value or an expression directly in global data or in local array */
static void init_putv(CType *type, Section *sec, unsigned long c, 
                      int v, int expr_type)
{
    int saved_global_expr, bt, bit_pos, bit_size;
    void *ptr;
    unsigned long long bit_mask;
    CType dtype;

    switch(expr_type) {
    case EXPR_VAL:
        vpushi(v);
        break;
    case EXPR_CONST:
        /* compound literals must be allocated globally in this case */
        saved_global_expr = global_expr;
        global_expr = 1;
        expr_const1();
        global_expr = saved_global_expr;
        /* NOTE: symbols are accepted */
        if ((vtop->r & (VT_VALMASK | VT_LVAL)) != VT_CONST)
            tcc_error("initializer element is not constant");
        break;
    case EXPR_ANY:
        expr_eq();
        break;
    }
    
    dtype = *type;
    dtype.t &= ~VT_CONSTANT; /* need to do that to avoid false warning */

    if (sec) {
        /* XXX: not portable */
        /* XXX: generate error if incorrect relocation */
        gen_assign_cast(&dtype);
        bt = type->t & VT_BTYPE;
        /* we'll write at most 16 bytes */
        if (c + 16 > sec->data_allocated) {
            section_realloc(sec, c + 16);
        }
        ptr = sec->data + c;
        /* XXX: make code faster ? */
        if (!(type->t & VT_BITFIELD)) {
            bit_pos = 0;
            bit_size = 32;
            bit_mask = -1LL;
        } else {
            bit_pos = (vtop->type.t >> VT_STRUCT_SHIFT) & 0x3f;
            bit_size = (vtop->type.t >> (VT_STRUCT_SHIFT + 6)) & 0x3f;
            bit_mask = (1LL << bit_size) - 1;
        }
        if ((vtop->r & VT_SYM) &&
            (bt == VT_BYTE ||
             bt == VT_SHORT ||
             bt == VT_DOUBLE ||
             bt == VT_LDOUBLE ||
             bt == VT_LLONG ||
             (bt == VT_INT && bit_size != 32)))
            tcc_error("initializer element is not computable at load time");
        switch(bt) {
            /* XXX: when cross-compiling we assume that each type has the
               same representation on host and target, which is likely to
               be wrong in the case of long double */
        case VT_BOOL:
            vtop->c.i = (vtop->c.i != 0);
        case VT_BYTE:
            *(char *)ptr |= (vtop->c.i & bit_mask) << bit_pos;
            break;
        case VT_SHORT:
            *(short *)ptr |= (vtop->c.i & bit_mask) << bit_pos;
            break;
        case VT_DOUBLE:
            *(double *)ptr = vtop->c.d;
            break;
        case VT_LDOUBLE:
            *(long double *)ptr = vtop->c.ld;
            break;
        case VT_LLONG:
            *(long long *)ptr |= (vtop->c.i & bit_mask) << bit_pos;
            break;
        case VT_PTR: {
            addr_t val = (vtop->c.i & bit_mask) << bit_pos;
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            if (vtop->r & VT_SYM)
                greloca(sec, vtop->sym, c, R_DATA_PTR, val);
            else
                *(addr_t *)ptr |= val;
#else
            if (vtop->r & VT_SYM)
                greloc(sec, vtop->sym, c, R_DATA_PTR);
            *(addr_t *)ptr |= val;
#endif
            break;
        }
        default: {
            int val = (vtop->c.i & bit_mask) << bit_pos;
#if defined(TCC_TARGET_ARM64) || defined(TCC_TARGET_X86_64)
            if (vtop->r & VT_SYM)
                greloca(sec, vtop->sym, c, R_DATA_PTR, val);
            else
                *(int *)ptr |= val;
#else
            if (vtop->r & VT_SYM)
                greloc(sec, vtop->sym, c, R_DATA_PTR);
            *(int *)ptr |= val;
#endif
            break;
        }
        }
        vtop--;
    } else {
        vset(&dtype, VT_LOCAL|VT_LVAL, c);
        vswap();
        vstore();
        vpop();
    }
}

/* put zeros for variable based init */
static void init_putz(CType *t, Section *sec, unsigned long c, int size)
{
    if (sec) {
        /* nothing to do because globals are already set to zero */
    } else {
        vpush_global_sym(&func_old_type, TOK_memset);
        vseti(VT_LOCAL, c);
#ifdef TCC_TARGET_ARM
        vpushs(size);
        vpushi(0);
#else
        vpushi(0);
        vpushs(size);
#endif
        gfunc_call(3);
    }
}

/* 't' contains the type and storage info. 'c' is the offset of the
   object in section 'sec'. If 'sec' is NULL, it means stack based
   allocation. 'first' is true if array '{' must be read (multi
   dimension implicit array init handling). 'size_only' is true if
   size only evaluation is wanted (only for arrays). */
static void decl_initializer(CType *type, Section *sec, unsigned long c, 
                             int first, int size_only)
{
    int index, array_length, n, no_oblock, nb, parlevel, parlevel1, i;
    int size1, align1, expr_type;
    Sym *s, *f;
    CType *t1;

    if (type->t & VT_VLA) {
        int a;
        
        /* save current stack pointer */
        if (vlas_in_scope == 0) {
            if (vla_sp_root_loc == -1)
                vla_sp_root_loc = (loc -= PTR_SIZE);
            gen_vla_sp_save(vla_sp_root_loc);
        }
        
        vla_runtime_type_size(type, &a);
        gen_vla_alloc(type, a);
        gen_vla_sp_save(c);
        vla_sp_loc = c;
        vlas_in_scope++;
    } else if (type->t & VT_ARRAY) {
        s = type->ref;
        n = s->c;
        array_length = 0;
        t1 = pointed_type(type);
        size1 = type_size(t1, &align1);

        no_oblock = 1;
        if ((first && tok != TOK_LSTR && tok != TOK_STR) || 
            tok == '{') {
            if (tok != '{')
                tcc_error("character array initializer must be a literal,"
                    " optionally enclosed in braces");
            skip('{');
            no_oblock = 0;
        }

        /* only parse strings here if correct type (otherwise: handle
           them as ((w)char *) expressions */
        if ((tok == TOK_LSTR && 
#ifdef TCC_TARGET_PE
             (t1->t & VT_BTYPE) == VT_SHORT && (t1->t & VT_UNSIGNED)
#else
             (t1->t & VT_BTYPE) == VT_INT
#endif
            ) || (tok == TOK_STR && (t1->t & VT_BTYPE) == VT_BYTE)) {
            while (tok == TOK_STR || tok == TOK_LSTR) {
                int cstr_len, ch;

                /* compute maximum number of chars wanted */
                if (tok == TOK_STR)
                    cstr_len = tokc.str.size;
                else
                    cstr_len = tokc.str.size / sizeof(nwchar_t);
                cstr_len--;
                nb = cstr_len;
                if (n >= 0 && nb > (n - array_length))
                    nb = n - array_length;
                if (!size_only) {
                    if (cstr_len > nb)
                        tcc_warning("initializer-string for array is too long");
                    /* in order to go faster for common case (char
                       string in global variable, we handle it
                       specifically */
                    if (sec && tok == TOK_STR && size1 == 1) {
                        memcpy(sec->data + c + array_length, tokc.str.data, nb);
                    } else {
                        for(i=0;i<nb;i++) {
                            if (tok == TOK_STR)
                                ch = ((unsigned char *)tokc.str.data)[i];
                            else
                                ch = ((nwchar_t *)tokc.str.data)[i];
                            init_putv(t1, sec, c + (array_length + i) * size1,
                                      ch, EXPR_VAL);
                        }
                    }
                }
                array_length += nb;
                next();
            }
            /* only add trailing zero if enough storage (no
               warning in this case since it is standard) */
            if (n < 0 || array_length < n) {
                if (!size_only) {
                    init_putv(t1, sec, c + (array_length * size1), 0, EXPR_VAL);
                }
                array_length++;
            }
        } else {
            index = 0;
            while (tok != '}') {
                decl_designator(type, sec, c, &index, NULL, size_only);
                if (n >= 0 && index >= n)
                    tcc_error("index too large");
                /* must put zero in holes (note that doing it that way
                   ensures that it even works with designators) */
                if (!size_only && array_length < index) {
                    init_putz(t1, sec, c + array_length * size1, 
                              (index - array_length) * size1);
                }
                index++;
                if (index > array_length)
                    array_length = index;
                /* special test for multi dimensional arrays (may not
                   be strictly correct if designators are used at the
                   same time) */
                if (index >= n && no_oblock)
                    break;
                if (tok == '}')
                    break;
                skip(',');
            }
        }
        if (!no_oblock)
            skip('}');
        /* put zeros at the end */
        if (!size_only && n >= 0 && array_length < n) {
            init_putz(t1, sec, c + array_length * size1, 
                      (n - array_length) * size1);
        }
        /* patch type size if needed */
        if (n < 0)
            s->c = array_length;
    } else if ((type->t & VT_BTYPE) == VT_STRUCT &&
               (sec || !first || tok == '{')) {

        /* NOTE: the previous test is a specific case for automatic
           struct/union init */
        /* XXX: union needs only one init */

        int par_count = 0;
        if (tok == '(') {
            AttributeDef ad1;
            CType type1;
            next();
	    if (tcc_state->old_struct_init_code) {
		/* an old version of struct initialization.
		   It have a problems. But with a new version
		   linux 2.4.26 can't load ramdisk.
		 */
        	while (tok == '(') {
            	    par_count++;
            	    next();
        	}
		if (!parse_btype(&type1, &ad1))
            	    expect("cast");
        	type_decl(&type1, &ad1, &n, TYPE_ABSTRACT);
		#if 0
		if (!is_assignable_types(type, &type1))
            	    tcc_error("invalid type for cast");
		#endif
		skip(')');
    	    }
    	    else
    	    {
              if (tok != '(') {
        	if (!parse_btype(&type1, &ad1))
            	    expect("cast");
        	type_decl(&type1, &ad1, &n, TYPE_ABSTRACT);
		#if 0
        	if (!is_assignable_types(type, &type1))
            	    tcc_error("invalid type for cast");
		#endif
        	skip(')');
    	      } else
		unget_tok(tok);
	    }
        }

        no_oblock = 1;
        if (first || tok == '{') {
            skip('{');
            no_oblock = 0;
        }
        s = type->ref;
        f = s->next;
        array_length = 0;
        index = 0;
        n = s->c;
        while (tok != '}') {
            decl_designator(type, sec, c, NULL, &f, size_only);
            index = f->c;
            if (!size_only && array_length < index) {
                init_putz(type, sec, c + array_length, 
                          index - array_length);
            }
            index = index + type_size(&f->type, &align1);
            if (index > array_length)
                array_length = index;

            /* gr: skip fields from same union - ugly. */
            while (f->next) {
        	int align = 0;
		int f_size = type_size(&f->type, &align);
		int f_type = (f->type.t & VT_BTYPE);

                ///printf("index: %2d %08x -- %2d %08x\n", f->c, f->type.t, f->next->c, f->next->type.t);
                /* test for same offset */
                if (f->next->c != f->c)
                    break;
                if ((f_type == VT_STRUCT) && (f_size == 0)) {
            	    /*
            	       Lets assume a structure of size 0 can't be a member of the union.
            	       This allow to compile the following code from a linux kernel v2.4.26
			    typedef struct { } rwlock_t;
			    struct fs_struct {
			     int count;
			     rwlock_t lock;
			     int umask;
			    };
			    struct fs_struct init_fs = { { (1) }, (rwlock_t) {}, 0022, };
			tcc-0.9.23 can succesfully compile this version of the kernel.
			gcc don't have problems with this code too.
            	    */
                    break;
                }
                /* if yes, test for bitfield shift */
                if ((f->type.t & VT_BITFIELD) && (f->next->type.t & VT_BITFIELD)) {
                    int bit_pos_1 = (f->type.t >> VT_STRUCT_SHIFT) & 0x3f;
                    int bit_pos_2 = (f->next->type.t >> VT_STRUCT_SHIFT) & 0x3f;
                    //printf("bitfield %d %d\n", bit_pos_1, bit_pos_2);
                    if (bit_pos_1 != bit_pos_2)
                        break;
                }
                f = f->next;
            }

            f = f->next;
            if (no_oblock && f == NULL)
                break;
            if (tok == '}')
                break;
            skip(',');
        }
        /* put zeros at the end */
        if (!size_only && array_length < n) {
            init_putz(type, sec, c + array_length, 
                      n - array_length);
        }
        if (!no_oblock)
            skip('}');
        while (par_count) {
            skip(')');
            par_count--;
        }
    } else if (tok == '{') {
        next();
        decl_initializer(type, sec, c, first, size_only);
        skip('}');
    } else if (size_only) {
        /* just skip expression */
        parlevel = parlevel1 = 0;
        while ((parlevel > 0 || parlevel1 > 0 ||
		(tok != '}' && tok != ',')) &&  tok != -1) {
            if (tok == '(')
                parlevel++;
            else if (tok == ')') {
		if (parlevel == 0 && parlevel1 == 0)
		    break;
                parlevel--;
            }
	    else if (tok == '{')
		parlevel1++;
	    else if (tok == '}') {
		if (parlevel == 0 && parlevel1 == 0)
		    break;
		parlevel1--;
	    }
            next();
        }
    } else {
        /* currently, we always use constant expression for globals
           (may change for scripting case) */
        expr_type = EXPR_CONST;
        if (!sec)
            expr_type = EXPR_ANY;
        init_putv(type, sec, c, 0, expr_type);
    }
}

/* parse an initializer for type 't' if 'has_init' is non zero, and
   allocate space in local or global data space ('r' is either
   VT_LOCAL or VT_CONST). If 'v' is non zero, then an associated
   variable 'v' of scope 'scope' is declared before initializers
   are parsed. If 'v' is zero, then a reference to the new object
   is put in the value stack. If 'has_init' is 2, a special parsing
   is done to handle string constants. */
static void decl_initializer_alloc(CType *type, AttributeDef *ad, int r, 
                                   int has_init, int v, int scope)
{
    int size, align, addr, data_offset;
    int level;
    ParseState saved_parse_state = {0};
    TokenString init_str;
    Section *sec;
    Sym *flexible_array;

    flexible_array = NULL;
    if ((type->t & VT_BTYPE) == VT_STRUCT) {
        Sym *field = type->ref->next;
        if (field) {
            while (field->next)
                field = field->next;
            if (field->type.t & VT_ARRAY && field->type.ref->c < 0)
                flexible_array = field;
        }
    }

    size = type_size(type, &align);
    /* If unknown size, we must evaluate it before
       evaluating initializers because
       initializers can generate global data too
       (e.g. string pointers or ISOC99 compound
       literals). It also simplifies local
       initializers handling */
    tok_str_new(&init_str);
    if (size < 0 || (flexible_array && has_init)) {
        if (!has_init) 
            tcc_error("unknown type size");
        /* get all init string */
        if (has_init == 2) {
            /* only get strings */
            while (tok == TOK_STR || tok == TOK_LSTR) {
                tok_str_add_tok(&init_str);
                next();
            }
        } else {
            level = 0;
            while (level > 0 || (tok != ',' && tok != ';')) {
                if (tok < 0)
                    tcc_error("unexpected end of file in initializer");
                tok_str_add_tok(&init_str);
                if (tok == '{')
                    level++;
                else if (tok == '}') {
                    level--;
                    if (level <= 0) {
                        next();
                        break;
                    }
                }
                next();
            }
        }
        tok_str_add(&init_str, -1);
        tok_str_add(&init_str, 0);
        
        /* compute size */
        save_parse_state(&saved_parse_state);

        begin_macro(&init_str, 0);
        next();
        decl_initializer(type, NULL, 0, 1, 1);
        /* prepare second initializer parsing */
        macro_ptr = init_str.str;
        next();
        
        /* if still unknown size, error */
        size = type_size(type, &align);
        if (size < 0) 
            tcc_error("unknown type size");
    }
    /* If there's a flex member and it was used in the initializer
       adjust size.  */
    if (flexible_array &&
	flexible_array->type.ref->c > 0)
        size += flexible_array->type.ref->c
	        * pointed_size(&flexible_array->type);
    /* take into account specified alignment if bigger */
    if (ad->a.aligned) {
        if (ad->a.aligned > align)
            align = ad->a.aligned;
    } else if (ad->a.packed) {
        align = 1;
    }
    if ((r & VT_VALMASK) == VT_LOCAL) {
        sec = NULL;
#ifdef CONFIG_TCC_BCHECK
        if (tcc_state->do_bounds_check && (type->t & VT_ARRAY)) {
            loc--;
        }
#endif
        loc = (loc - size) & -align;
        addr = loc;
#ifdef CONFIG_TCC_BCHECK
        /* handles bounds */
        /* XXX: currently, since we do only one pass, we cannot track
           '&' operators, so we add only arrays */
        if (tcc_state->do_bounds_check && (type->t & VT_ARRAY)) {
            addr_t *bounds_ptr;
            /* add padding between regions */
            loc--;
            /* then add local bound info */
            bounds_ptr = section_ptr_add(lbounds_section, 2 * sizeof(addr_t));
            bounds_ptr[0] = addr;
            bounds_ptr[1] = size;
        }
#endif
        if (v) {
            /* local variable */
            sym_push(v, type, r, addr);
        } else {
            /* push local reference */
            vset(type, r, addr);
        }
    } else {
        Sym *sym;

        sym = NULL;
        if (v && scope == VT_CONST) {
            /* see if the symbol was already defined */
            sym = sym_find(v);
            if (sym) {
                if (!is_compatible_types(&sym->type, type))
                    tcc_error("incompatible types for redefinition of '%s'", 
                          get_tok_str(v, NULL));
                if (sym->type.t & VT_EXTERN) {
                    /* if the variable is extern, it was not allocated */
                    sym->type.t &= ~VT_EXTERN;
                    /* set array size if it was omitted in extern
                       declaration */
                    if ((sym->type.t & VT_ARRAY) && 
                        sym->type.ref->c < 0 &&
                        type->ref->c >= 0)
                        sym->type.ref->c = type->ref->c;
                } else {
                    /* we accept several definitions of the same
                       global variable. this is tricky, because we
                       must play with the SHN_COMMON type of the symbol */
                    /* XXX: should check if the variable was already
                       initialized. It is incorrect to initialized it
                       twice */
                    /* no init data, we won't add more to the symbol */
                    if (!has_init)
                        goto no_alloc;
                }
            }
        }

        /* allocate symbol in corresponding section */
        sec = ad->section;
        if (!sec) {
            if (has_init)
                sec = data_section;
            else if (tcc_state->nocommon)
                sec = bss_section;
        }
        if (sec) {
            data_offset = sec->data_offset;
            data_offset = (data_offset + align - 1) & -align;
            addr = data_offset;
            /* very important to increment global pointer at this time
               because initializers themselves can create new initializers */
            data_offset += size;
#ifdef CONFIG_TCC_BCHECK
            /* add padding if bound check */
            if (tcc_state->do_bounds_check)
                data_offset++;
#endif
            sec->data_offset = data_offset;
            /* allocate section space to put the data */
            if (sec->sh_type != SHT_NOBITS && 
                data_offset > sec->data_allocated)
                section_realloc(sec, data_offset);
            /* align section if needed */
            if (align > sec->sh_addralign)
                sec->sh_addralign = align;
        } else {
            addr = 0; /* avoid warning */
        }

        if (v) {
            if (scope != VT_CONST || !sym) {
                sym = sym_push(v, type, r | VT_SYM, 0);
                sym->asm_label = ad->asm_label;
            }
            /* update symbol definition */
            if (sec) {
                put_extern_sym(sym, sec, addr, size);
            } else {
                ElfW(Sym) *esym;
                /* put a common area */
                put_extern_sym(sym, NULL, align, size);
                /* XXX: find a nicer way */
                esym = &((ElfW(Sym) *)symtab_section->data)[sym->c];
                esym->st_shndx = SHN_COMMON;
            }
        } else {
            /* push global reference */
            sym = get_sym_ref(type, sec, addr, size);
	    vpushsym(type, sym);
        }
        /* patch symbol weakness */
        if (type->t & VT_WEAK)
            weaken_symbol(sym);
	apply_visibility(sym, type);
#ifdef CONFIG_TCC_BCHECK
        /* handles bounds now because the symbol must be defined
           before for the relocation */
        if (tcc_state->do_bounds_check) {
            addr_t *bounds_ptr;

            greloc(bounds_section, sym, bounds_section->data_offset, R_DATA_PTR);
            /* then add global bound info */
            bounds_ptr = section_ptr_add(bounds_section, 2 * sizeof(addr_t));
            bounds_ptr[0] = 0; /* relocated */
            bounds_ptr[1] = size;
        }
#endif
    }
    if (has_init || (type->t & VT_VLA)) {
        decl_initializer(type, sec, addr, 1, 0);
        /* restore parse state if needed */
        if (init_str.str) {
            end_macro();
            restore_parse_state(&saved_parse_state);
        }
        /* patch flexible array member size back to -1, */
        /* for possible subsequent similar declarations */
        if (flexible_array)
            flexible_array->type.ref->c = -1;
    }
 no_alloc: ;
}

static void put_func_debug(Sym *sym)
{
    char buf[512];

    /* stabs info */
    /* XXX: we put here a dummy type */
    snprintf(buf, sizeof(buf), "%s:%c1", 
             funcname, sym->type.t & VT_STATIC ? 'f' : 'F');
    put_stabs_r(buf, N_FUN, 0, file->line_num, 0,
                cur_text_section, sym->c);
    /* //gr gdb wants a line at the function */
    put_stabn(N_SLINE, 0, file->line_num, 0); 
    last_ind = 0;
    last_line_num = 0;
}

/* parse an old style function declaration list */
/* XXX: check multiple parameter */
static void func_decl_list(Sym *func_sym)
{
    AttributeDef ad;
    int v;
    Sym *s;
    CType btype, type;

    /* parse each declaration */
    while (tok != '{' && tok != ';' && tok != ',' && tok != TOK_EOF &&
           tok != TOK_ASM1 && tok != TOK_ASM2 && tok != TOK_ASM3) {
        if (!parse_btype(&btype, &ad)) 
            expect("declaration list");
        if (((btype.t & VT_BTYPE) == VT_ENUM ||
             (btype.t & VT_BTYPE) == VT_STRUCT) && 
            tok == ';') {
            /* we accept no variable after */
        } else {
            for(;;) {
                type = btype;
                type_decl(&type, &ad, &v, TYPE_DIRECT);
                /* find parameter in function parameter list */
                s = func_sym->next;
                while (s != NULL) {
                    if ((s->v & ~SYM_FIELD) == v)
                        goto found;
                    s = s->next;
                }
                tcc_error("declaration for parameter '%s' but no such parameter",
                      get_tok_str(v, NULL));
            found:
                /* check that no storage specifier except 'register' was given */
                if (type.t & VT_STORAGE)
                    tcc_error("storage class specified for '%s'", get_tok_str(v, NULL)); 
                convert_parameter_type(&type);
                /* we can add the type (NOTE: it could be local to the function) */
                s->type = type;
                /* accept other parameters */
                if (tok == ',')
                    next();
                else
                    break;
            }
        }
        skip(';');
    }
}

/* parse a function defined by symbol 'sym' and generate its code in
   'cur_text_section' */
static void gen_function(Sym *sym)
{
    int saved_nocode_wanted = nocode_wanted;

    nocode_wanted = 0;
    ind = cur_text_section->data_offset;
    /* NOTE: we patch the symbol size later */
    put_extern_sym(sym, cur_text_section, ind, 0);
    funcname = get_tok_str(sym->v, NULL);
    func_ind = ind;
    /* Initialize VLA state */
    vla_sp_loc = -1;
    vla_sp_root_loc = -1;
    /* put debug symbol */
    if (tcc_state->do_debug)
        put_func_debug(sym);

    /* push a dummy symbol to enable local sym storage */
    sym_push2(&local_stack, SYM_FIELD, 0, 0);
    local_scope = 1; /* for function parameters */
    gfunc_prolog(&sym->type);
    local_scope = 0;

#ifdef CONFIG_TCC_BCHECK
    if (tcc_state->do_bounds_check && !strcmp(funcname, "main")) {
        int i;
        Sym *sym;
        for (i = 0, sym = local_stack; i < 2; i++, sym = sym->prev) {
            if (sym->v & SYM_FIELD || sym->prev->v & SYM_FIELD)
                break;
            vpush_global_sym(&func_old_type, TOK___bound_main_arg);
            vset(&sym->type, sym->r, sym->c);
            gfunc_call(1);
        }
    }
#endif
    rsym = 0;
    block(NULL, NULL, NULL, NULL, 0, 0);
    gsym(rsym);
    gfunc_epilog();
    cur_text_section->data_offset = ind;
    label_pop(&global_label_stack, NULL);
    /* reset local stack */
    local_scope = 0;
    sym_pop(&local_stack, NULL);
    /* end of function */
    /* patch symbol size */
    ((ElfW(Sym) *)symtab_section->data)[sym->c].st_size = 
        ind - func_ind;
    /* patch symbol weakness (this definition overrules any prototype) */
    if (sym->type.t & VT_WEAK)
        weaken_symbol(sym);
    apply_visibility(sym, &sym->type);
    if (tcc_state->do_debug) {
        put_stabn(N_FUN, 0, 0, ind - func_ind);
    }
    /* It's better to crash than to generate wrong code */
    cur_text_section = NULL;
    funcname = ""; /* for safety */
    func_vt.t = VT_VOID; /* for safety */
    func_var = 0; /* for safety */
    ind = 0; /* for safety */
    nocode_wanted = saved_nocode_wanted;
    check_vstack();
}

ST_FUNC void gen_inline_functions(void)
{
    Sym *sym;
    int inline_generated, i, ln;
    struct InlineFunc *fn;

    ln = file->line_num;
    /* iterate while inline function are referenced */
    for(;;) {
        inline_generated = 0;
        for (i = 0; i < tcc_state->nb_inline_fns; ++i) {
            fn = tcc_state->inline_fns[i];
            sym = fn->sym;
            if (sym && sym->c) {
                /* the function was used: generate its code and
                   convert it to a normal function */
                fn->sym = NULL;
                if (file)
                    pstrcpy(file->filename, sizeof file->filename, fn->filename);
                sym->r = VT_SYM | VT_CONST;
                sym->type.t &= ~VT_INLINE;

                begin_macro(&fn->func_str, 0);
                next();
                cur_text_section = text_section;
                gen_function(sym);
                end_macro();

                inline_generated = 1;
            }
        }
        if (!inline_generated)
            break;
    }
    file->line_num = ln;
    /* free tokens of unused inline functions */
    for (i = 0; i < tcc_state->nb_inline_fns; ++i) {
        fn = tcc_state->inline_fns[i];
        if (fn->sym)
            tok_str_free(fn->func_str.str);
    }
    dynarray_reset(&tcc_state->inline_fns, &tcc_state->nb_inline_fns);
}

/* 'l' is VT_LOCAL or VT_CONST to define default storage type */
static int decl0(int l, int is_for_loop_init)
{
    int v, has_init, r;
    CType type, btype;
    Sym *sym;
    AttributeDef ad;

    while (1) {
        if (!parse_btype(&btype, &ad)) {
            if (is_for_loop_init)
                return 0;
            /* skip redundant ';' */
            /* XXX: find more elegant solution */
            if (tok == ';') {
                next();
                continue;
            }
            if (l == VT_CONST &&
                (tok == TOK_ASM1 || tok == TOK_ASM2 || tok == TOK_ASM3)) {
                /* global asm block */
                asm_global_instr();
                continue;
            }
            /* special test for old K&R protos without explicit int
               type. Only accepted when defining global data */
            if (l == VT_LOCAL || tok < TOK_DEFINE)
                break;
            btype.t = VT_INT;
        }
        if (((btype.t & VT_BTYPE) == VT_ENUM ||
             (btype.t & VT_BTYPE) == VT_STRUCT) && 
            tok == ';') {
	    if ((btype.t & VT_BTYPE) == VT_STRUCT) {
		int v = btype.ref->v;
		if (!(v & SYM_FIELD) && (v & ~SYM_STRUCT) >= SYM_FIRST_ANOM)
        	    tcc_warning("unnamed struct/union that defines no instances");
	    }
            next();
            continue;
        }
        while (1) { /* iterate thru each declaration */
            type = btype;
            type_decl(&type, &ad, &v, TYPE_DIRECT);
#if 0
            {
                char buf[500];
                type_to_str(buf, sizeof(buf), t, get_tok_str(v, NULL));
                printf("type = '%s'\n", buf);
            }
#endif
            if ((type.t & VT_BTYPE) == VT_FUNC) {
                if ((type.t & VT_STATIC) && (l == VT_LOCAL)) {
                    tcc_error("function without file scope cannot be static");
                }
                /* if old style function prototype, we accept a
                   declaration list */
                sym = type.ref;
                if (sym->c == FUNC_OLD)
                    func_decl_list(sym);
            }

            if (gnu_ext && (tok == TOK_ASM1 || tok == TOK_ASM2 || tok == TOK_ASM3)) {
                ad.asm_label = asm_label_instr();
                /* parse one last attribute list, after asm label */
                parse_attribute(&ad);
                if (tok == '{')
                    expect(";");
            }

            if (ad.a.weak)
                type.t |= VT_WEAK;
#ifdef TCC_TARGET_PE
            if (ad.a.func_import)
                type.t |= VT_IMPORT;
            if (ad.a.func_export)
                type.t |= VT_EXPORT;
#endif
	    type.t |= ad.a.visibility << VT_VIS_SHIFT;

            if (tok == '{') {
                if (l == VT_LOCAL)
                    tcc_error("cannot use local functions");
                if ((type.t & VT_BTYPE) != VT_FUNC)
                    expect("function definition");

                /* reject abstract declarators in function definition */
                sym = type.ref;
                while ((sym = sym->next) != NULL)
                    if (!(sym->v & ~SYM_FIELD))
                       expect("identifier");
                
                /* XXX: cannot do better now: convert extern line to static inline */
                if ((type.t & (VT_EXTERN | VT_INLINE)) == (VT_EXTERN | VT_INLINE))
                    type.t = (type.t & ~VT_EXTERN) | VT_STATIC;
                
                sym = sym_find(v);
                if (sym) {
                    Sym *ref;
                    if ((sym->type.t & VT_BTYPE) != VT_FUNC)
                        goto func_error1;

                    ref = sym->type.ref;
                    if (0 == ref->a.func_proto)
                        tcc_error("redefinition of '%s'", get_tok_str(v, NULL));

                    /* use func_call from prototype if not defined */
                    if (ref->a.func_call != FUNC_CDECL
                     && type.ref->a.func_call == FUNC_CDECL)
                        type.ref->a.func_call = ref->a.func_call;

                    /* use export from prototype */
                    if (ref->a.func_export)
                        type.ref->a.func_export = 1;

                    /* use static from prototype */
                    if (sym->type.t & VT_STATIC)
                        type.t = (type.t & ~VT_EXTERN) | VT_STATIC;

		    /* If the definition has no visibility use the
		       one from prototype.  */
		    if (! (type.t & VT_VIS_MASK))
		        type.t |= sym->type.t & VT_VIS_MASK;

                    if (!is_compatible_types(&sym->type, &type)) {
                    func_error1:
                        tcc_error("incompatible types for redefinition of '%s'", 
                              get_tok_str(v, NULL));
                    }
                    type.ref->a.func_proto = 0;
                    /* if symbol is already defined, then put complete type */
                    sym->type = type;
                } else {
                    /* put function symbol */
                    sym = global_identifier_push(v, type.t, 0);
                    sym->type.ref = type.ref;
                }

                /* static inline functions are just recorded as a kind
                   of macro. Their code will be emitted at the end of
                   the compilation unit only if they are used */
                if ((type.t & (VT_INLINE | VT_STATIC)) == 
                    (VT_INLINE | VT_STATIC)) {
                    int block_level;
                    struct InlineFunc *fn;
                    const char *filename;
                           
                    filename = file ? file->filename : "";
                    fn = tcc_malloc(sizeof *fn + strlen(filename));
                    strcpy(fn->filename, filename);
                    fn->sym = sym;
                    tok_str_new(&fn->func_str);
                    
                    block_level = 0;
                    for(;;) {
                        int t;
                        if (tok == TOK_EOF)
                            tcc_error("unexpected end of file");
                        tok_str_add_tok(&fn->func_str);
                        t = tok;
                        next();
                        if (t == '{') {
                            block_level++;
                        } else if (t == '}') {
                            block_level--;
                            if (block_level == 0)
                                break;
                        }
                    }
                    tok_str_add(&fn->func_str, -1);
                    tok_str_add(&fn->func_str, 0);
                    dynarray_add((void ***)&tcc_state->inline_fns, &tcc_state->nb_inline_fns, fn);

                } else {
                    /* compute text section */
                    cur_text_section = ad.section;
                    if (!cur_text_section)
                        cur_text_section = text_section;
                    sym->r = VT_SYM | VT_CONST;
                    gen_function(sym);
                }
                break;
            } else {
                if (btype.t & VT_TYPEDEF) {
                    /* save typedefed type  */
                    /* XXX: test storage specifiers ? */
                    sym = sym_find(v);
                    if (sym && sym->scope == local_scope) {
                        if (!is_compatible_types(&sym->type, &type)
                            || !(sym->type.t & VT_TYPEDEF))
                            tcc_error("incompatible redefinition of '%s'",
                                get_tok_str(v, NULL));
                        sym->type = type;
                    } else {
                        sym = sym_push(v, &type, 0, 0);
                    }
                    sym->a = ad.a;
                    sym->type.t |= VT_TYPEDEF;
                } else {
                    r = 0;
                    if ((type.t & VT_BTYPE) == VT_FUNC) {
                        /* external function definition */
                        /* specific case for func_call attribute */
                        ad.a.func_proto = 1;
                        type.ref->a = ad.a;
                    } else if (!(type.t & VT_ARRAY)) {
                        /* not lvalue if array */
                        r |= lvalue_type(type.t);
                    }
                    has_init = (tok == '=');
                    if (has_init && (type.t & VT_VLA))
                        tcc_error("Variable length array cannot be initialized");
                    if ((btype.t & VT_EXTERN) || ((type.t & VT_BTYPE) == VT_FUNC) ||
                        ((type.t & VT_ARRAY) && (type.t & VT_STATIC) &&
                         !has_init && l == VT_CONST && type.ref->c < 0)) {
                        /* external variable or function */
                        /* NOTE: as GCC, uninitialized global static
                           arrays of null size are considered as
                           extern */
                        sym = external_sym(v, &type, r);
                        sym->asm_label = ad.asm_label;

                        if (ad.alias_target) {
                            Section tsec;
                            Elf32_Sym *esym;
                            Sym *alias_target;

                            alias_target = sym_find(ad.alias_target);
                            if (!alias_target || !alias_target->c)
                                tcc_error("unsupported forward __alias__ attribute");
                            esym = &((Elf32_Sym *)symtab_section->data)[alias_target->c];
                            tsec.sh_num = esym->st_shndx;
                            put_extern_sym2(sym, &tsec, esym->st_value, esym->st_size, 0);
                        }
                    } else {
                        type.t |= (btype.t & VT_STATIC); /* Retain "static". */
                        if (type.t & VT_STATIC)
                            r |= VT_CONST;
                        else
                            r |= l;
                        if (has_init)
                            next();
                        decl_initializer_alloc(&type, &ad, r, has_init, v, l);
                    }
                }
                if (tok != ',') {
                    if (is_for_loop_init)
                        return 1;
                    skip(';');
                    break;
                }
                next();
            }
            ad.a.aligned = 0;
        }
    }
    return 0;
}

ST_FUNC void decl(int l)
{
    decl0(l, 0);
}
