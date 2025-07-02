/*
** LoongArch instruction emitter.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice in luajit.h
** Copyright (C) 2025 Loongson Technology. All rights reserved.
*/

static intptr_t get_k64val(ASMState *as, IRRef ref)
{
  IRIns *ir = IR(ref);
  if (ir->o == IR_KINT64) {
    return (intptr_t)ir_kint64(ir)->u64;
  } else if (ir->o == IR_KGC) {
    return (intptr_t)ir_kgc(ir);
  } else if (ir->o == IR_KPTR || ir->o == IR_KKPTR) {
    return (intptr_t)ir_kptr(ir);
  } else {
    lj_assertA(ir->o == IR_KINT || ir->o == IR_KNULL,
               "bad 64 bit const IR op %d", ir->o);
    return ir->i;  /* Sign-extended. */
  }
}

#define get_kval(as, ref)       get_k64val(as, ref)

/* -- Emit basic instructions --------------------------------------------- */

static void emit_djk(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, Reg rk)
{
  *--as->mcp = loongi | LOONGF_D(rd&0x1f) | LOONGF_J(rj&0x1f) | LOONGF_K(rk&0x1f);
}

#define emit_dj(as, loongi, rd, rj)         emit_djk(as, loongi, rd, rj, 0)

static void emit_dju5(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, uint32_t u)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_I5(u);
}

static void emit_dju6(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, uint32_t u)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_I6(u);
}

static void emit_djs12(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, int32_t i)
{
  *--as->mcp = loongi | LOONGF_D(rd&0x1f) | LOONGF_J(rj) | LOONGF_I12(i);
}

static void emit_dju12(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, uint32_t u)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_I12(u);
}

static void emit_djs16(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, int32_t i)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_I16(i);
}

static void emit_ds20(ASMState *as, LOONGIns loongi, Reg rd, int32_t i)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_I20(i);
}

#define checki12(x)	LOONGF_S_OK(x, 12)
#define checku12(x)	((x) == ((x) & 0xfff))

static Reg ra_allock(ASMState *as, intptr_t k, RegSet allow);
static void ra_allockreg(ASMState *as, intptr_t k, Reg r);
static Reg ra_scratch(ASMState *as, RegSet allow);

static void emit_djml(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, uint32_t m, uint32_t l)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_L(l) | LOONGF_M(m);
}

static void emit_djka(ASMState *as, LOONGIns loongi, Reg rd, Reg rj, Reg rk, Reg ra)
{
  *--as->mcp = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_K(rk) | LOONGF_A(ra);
}

static void emit_b_bl(ASMState *as, LOONGIns loongi, uint32_t i)
{
  *--as->mcp = loongi | LOONGF_I26(i);
}


/* -- Emit loads/stores --------------------------------------------------- */

/* Prefer rematerialization of BASE/L from global_State over spills. */
#define emit_canremat(ref)	((ref) <= REF_BASE)


/* Load a signed 32 bit constant into a GPR. */
static void emit_loads32(ASMState *as, Reg r, int32_t i)
{
  emit_dju12(as, LOONGI_ORI, r, r, i);
  emit_ds20(as, LOONGI_LU12I_W, r, i>>12);
}

/* Load a int type value into a GPR. */
static void emit_loadi(ASMState *as, Reg r, int32_t i)
{
  if (checki12(i)) {
    *--as->mcp = LOONGI_ADDI_D | LOONGF_D(r) | LOONGF_J(RID_ZERO) | LOONGF_I12(i);
  } else {
    emit_loads32(as, r, i);
  }
}

/* Load a 64 bit constant into a GPR. */
static void emit_loadu64(ASMState *as, Reg r, uint64_t u64)
{
  if (checki32((int64_t)u64)) {
    emit_loadi(as, r, (int32_t)u64);
  } else {
    *--as->mcp = LOONGI_LU52I_D | LOONGF_D(r) | LOONGF_J(r) | LOONGF_I12(u64>>52);
    *--as->mcp = LOONGI_LU32I_D | LOONGF_D(r) | LOONGF_I20(u64>>32);
    *--as->mcp = LOONGI_ORI | LOONGF_D(r) | LOONGF_J(r) | LOONGF_I12(u64);
    *--as->mcp = LOONGI_LU12I_W | LOONGF_D(r) | LOONGF_I20(u64>>12);
  }
}

static void emit_lso(ASMState *as, LOONGIns loongi, Reg dest, Reg src, int64_t i, RegSet allow)
{
  if (checki12(i)) {
    emit_djs12(as, loongi, dest, src, i);
  } else {
    LOONGIns loongk = LOONGI_NOP;
    switch (loongi) {
    case LOONGI_LD_D: loongk = LOONGI_LDX_D; break;
    case LOONGI_LD_W: loongk = LOONGI_LDX_W; break;
    case LOONGI_ST_D: loongk = LOONGI_STX_D; break;
    case LOONGI_FLD_D: loongk = LOONGI_FLDX_D; break;
    case LOONGI_FST_D: loongk = LOONGI_FSTX_D; break;
    case LOONGI_LD_B: loongk = LOONGI_LDX_B; break;
    case LOONGI_LD_BU: loongk = LOONGI_LDX_BU; break;
    case LOONGI_LD_H: loongk = LOONGI_LDX_H; break;
    case LOONGI_LD_HU: loongk = LOONGI_LDX_HU; break;
    case LOONGI_FLD_S: loongk = LOONGI_FLDX_S; break;
    default: break;
    }
    Reg ofs = ra_scratch(as, allow);
    emit_djk(as, loongk, dest, src, ofs);
    emit_loads32(as, ofs, i);
  }
}

#define emit_loada(as, r, addr)         emit_loadu64(as, (r), u64ptr((addr)))

/* Get/set from constant pointer. */
static void emit_lsptr(ASMState *as, LOONGIns loongi, Reg r, void *p, RegSet allow)
{
  intptr_t jgl = (intptr_t)(J2G(as->J));
  int32_t ofs = (intptr_t)(p)-jgl;
  emit_lso(as, loongi, r, RID_JGL, ofs, allow);
}

/* Load 64 bit IR constant into register. */
static void emit_loadk64(ASMState *as, Reg r, IRIns *ir)
{
  const uint64_t *k = &ir_k64(ir)->u64;
  Reg r64 = r;
  if (rset_test(RSET_FPR, r)) {
    r64 = RID_TMP;
    emit_dj(as, LOONGI_MOVGR2FR_D, r, r64);
  }
  if (checki12((intptr_t)k-(intptr_t)J2G(as->J)))
    emit_lsptr(as, LOONGI_LD_D, r64, (void *)k, 0);  /*To copy a doubleword from a GPR to an FPR*/
  else
    emit_loadu64(as, r64, *k);
}

/* Get/set global_State fields. */
static void emit_lsglptr2(ASMState *as, LOONGIns loongi, Reg r, int32_t ofs)
{
  emit_djs12(as, loongi, r, RID_JGL, ofs);
}

#define emit_getgl(as, r, field) \
  emit_lsglptr2(as, LOONGI_LD_D, (r), (int32_t)offsetof(global_State, field))
#define emit_setgl(as, r, field) \
  emit_lsglptr2(as, LOONGI_ST_D, (r), (int32_t)offsetof(global_State, field))

/* Trace number is determined from per-trace exit stubs. */
#define emit_setvmstate(as, i)		UNUSED(i)

/* -- Emit control-flow instructions -------------------------------------- */

/* Label for internal jumps. */
typedef MCode *MCLabel;

/* Return label pointing to current PC. */
#define emit_label(as)		((as)->mcp)

static void emit_branch(ASMState *as, LOONGIns loongi, Reg rj, Reg rd, MCode *target)
{
  MCode *p = as->mcp;
  ptrdiff_t delta = target - (p - 1);
  lj_assertA(((delta + 0x8000) >> 16) == 0, "branch target out of range");
  /* BEQ BNE BGE BLZ */
  *--p = loongi | LOONGF_D(rd) | LOONGF_J(rj) | LOONGF_I16(delta);
  as->mcp = p;
}

static void emit_branch21(ASMState *as, LOONGIns loongi, Reg rj, MCode *target)
{
  MCode *p = as->mcp;
  ptrdiff_t delta = target - (p - 1);
  lj_assertA(((delta + 0x100000) >> 21) == 0, "branch target out of range");
  /* BEQZ BNEZ BCEQZ BCNEZ */
  *--p = loongi | LOONGF_J(rj) | LOONGF_I21(delta);
  as->mcp = p;
}

static void emit_jmp(ASMState *as, MCode *target)
{
  MCode *p = as->mcp;
  ptrdiff_t delta = target - (p - 1);
  emit_b_bl(as, LOONGI_B, delta);  /* offs 26 */
}

#define emit_move(as, dst, src) \
  emit_djk(as, LOONGI_OR, (dst), (src), RID_ZERO)

static void emit_call(ASMState *as, void *target)
{
  MCode *p = --as->mcp;
  ptrdiff_t delta = (char *)target - (char *)p;
  if (LOONGF_S_OK(delta>>2, 26)) {
    *p = LOONGI_BL | LOONGF_I26(delta>>2);
  } else {  /* Target out of range: need indirect call. */
    Reg r = ra_allock(as, (intptr_t)target, RSET_RANGE(RID_R12, RID_R19+1));
    *p = LOONGI_JIRL | LOONGF_D(RID_RA) | LOONGF_J(r) | LOONGF_I16(0);
  }
}

/* -- Emit generic operations --------------------------------------------- */

/* Generic move between two regs. */
static void emit_movrr(ASMState *as, IRIns *ir, Reg dst, Reg src)
{
  if (dst < RID_MAX_GPR && src >= RID_MIN_FPR) {  /* FR to GR */
    emit_dj(as, irt_isnum(ir->t) ? LOONGI_MOVFR2GR_D : LOONGI_MOVFR2GR_S, dst, src);
  } else if (dst < RID_MAX_GPR) {  /* GR to GR */
    emit_move(as, dst, src);
  } else if (dst >= RID_MIN_FPR  && src < RID_MAX_GPR) {  /* GR to FR */
    emit_dj(as, irt_isnum(ir->t) ? LOONGI_MOVGR2FR_D : LOONGI_MOVGR2FR_W, dst, src);
  } else {  /* FR to FR */
    emit_dj(as, irt_isnum(ir->t) ? LOONGI_FMOV_D : LOONGI_FMOV_S, dst, src);
  }
}

/* Emit an arithmetic operation with a constant operand. */
static void emit_addk(ASMState *as, Reg dest, Reg src, int32_t i, RegSet allow)
{
  if (checki12(i)) {
    emit_djs12(as, LOONGI_ADDI_D, dest, src, i);
  } else {
    Reg src2 = ra_allock(as, i, allow);
    emit_djk(as, LOONGI_ADD_D, dest, src, src2);
  }
}

/* Generic load of register with base and (small) offset address. */
static void emit_loadofs(ASMState *as, IRIns *ir, Reg r, Reg base, int32_t ofs)
{
  if (r < RID_MAX_GPR) {
    emit_djs12(as, irt_is64(ir->t) ? LOONGI_LD_D : LOONGI_LD_W, r, base, ofs);
  } else {
    emit_djs12(as, irt_isnum(ir->t) ? LOONGI_FLD_D : LOONGI_FLD_S, r, base, ofs);
  }
}

/* Generic store of register with base and (small) offset address. */
static void emit_storeofs(ASMState *as, IRIns *ir, Reg r, Reg base, int32_t ofs)
{
  if (r < RID_MAX_GPR) {
    emit_djs12(as, irt_is64(ir->t) ? LOONGI_ST_D : LOONGI_ST_W, r, base, ofs);
  } else {
    emit_djs12(as, irt_isnum(ir->t) ? LOONGI_FST_D : LOONGI_FST_S, r, base, ofs);
  }
}

/* Add offset to pointer. */
static void emit_addptr(ASMState *as, Reg r, int32_t ofs)
{
  if (ofs) {
    emit_addk(as, r, r, ofs, rset_exclude(RSET_GPR, r));
  }
}


#define emit_spsub(as, ofs)	emit_addptr(as, RID_SP, -(ofs))
