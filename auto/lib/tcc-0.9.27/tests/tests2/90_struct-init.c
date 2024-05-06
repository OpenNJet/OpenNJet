typedef unsigned char u8;
typedef struct {} empty_s;
struct contains_empty {
    u8 a;
    empty_s empty;
    u8 b;
};
struct contains_empty ce = { { (1) }, (empty_s){}, 022, };
/* The following decl of 'q' would demonstrate the TCC bug in init_putv when
   handling copying compound literals.  (Compound literals
   aren't acceptable constant initializers in isoc99, but
   we accept them like gcc, except for this case)
//char *q = (char *){ "trara" }; */
struct SS {u8 a[3], b; };
struct SS sinit16[] = { { 1 }, 2 };
struct S
{
  u8 a,b;
  u8 c[2];
};

struct T
{
  u8 s[16];
  u8 a;
};

struct U
{
  u8 a;
  struct S s;
  u8 b;
  struct T t;
};

struct V
{
  struct S s;
  struct T t;
  u8 a;
};

struct W
{
  struct V t;
  struct S s[];
};

struct S gs = ((struct S){1, 2, 3, 4});
struct S gs2 = {1, 2, {3, 4}};
struct T gt = {"hello", 42};
struct U gu = {3, 5,6,7,8, 4, "huhu", 43};
struct U gu2 = {3, {5,6,7,8}, 4, {"huhu", 43}};
/* Optional braces around scalar initializers.  Accepted, but with
   a warning.  */
struct U gu3 = { {3}, {5,6,7,8,}, 4, {"huhu", 43}};
/* Many superfluous braces and leaving out one initializer for U.s.c[1] */
struct U gu4 = { 3, {5,6,7,},  5, { "bla", {44}} };
/* Superfluous braces and useless parens around values */
struct S gs3 = { (1), {(2)}, {(((3))), {4}}};
/* Superfluous braces, and leaving out braces for V.t, plus cast */
struct V gv = {{{3},4,{5,6}}, "haha", (u8)45, 46};
/* Compound literal */
struct V gv2 = {(struct S){7,8,{9,10}}, {"hihi", 47}, 48};
/* Parens around compound literal */
struct V gv3 = {((struct S){7,8,{9,10}}), {"hoho", 49}, 50};
/* Initialization of a flex array member (warns in GCC) */
struct W gw = {{1,2,3,4}, {1,2,3,4,5}};

union UU {
    u8 a;
    u8 b;
};
struct SU {
    union UU u;
    u8 c;
};
struct SU gsu = {5,6};

/* Unnamed struct/union members aren't ISO C, but it's a widely accepted
   extension.  See below for further extensions to that under -fms-extension.*/
union UV {
    struct {u8 a,b;};
    struct S s;
};
union UV guv = {{6,5}};
union UV guv2 = {{.b = 7, .a = 8}};
union UV guv3 = {.b = 8, .a = 7};

/* Under -fms-extensions also the following is valid:
union UV2 {
    struct Anon {u8 a,b;};    // unnamed member, but tagged struct, ...
    struct S s;
};
struct Anon gan = { 10, 11 }; // ... which makes it available here.
union UV2 guv4 = {{4,3}};     // and the other inits from above as well
*/

struct in6_addr {
    union {
	u8 u6_addr8[16];
	unsigned short u6_addr16[8];
    } u;
};
struct flowi6 {
    struct in6_addr saddr, daddr;
};
struct pkthdr {
    struct in6_addr daddr, saddr;
};
struct pkthdr phdr = { { { 6,5,4,3 } }, { { 9,8,7,6 } } };

struct Wrap {
    void *func;
};
int global;
void inc_global (void)
{
  global++;
}

struct Wrap global_wrap[] = {
    ((struct Wrap) {inc_global}),
    inc_global,
};

#include <stdio.h>
void print_ (const char *name, const u8 *p, long size)
{
  printf ("%s:", name);
  while (size--) {
      printf (" %x", *p++);
  }
  printf ("\n");
}
#define print(x) print_(#x, (u8*)&x, sizeof (x))
#if 1
void foo (struct W *w, struct pkthdr *phdr_)
{
  struct S ls = {1, 2, 3, 4};
  struct S ls2 = {1, 2, {3, 4}};
  struct T lt = {"hello", 42};
  struct U lu = {3, 5,6,7,8, 4, "huhu", 43};
  struct U lu1 = {3, ls, 4, {"huhu", 43}};
  struct U lu2 = {3, (ls), 4, {"huhu", 43}};
  const struct S *pls = &ls;
  struct S ls21 = *pls;
  struct U lu22 = {3, *pls, 4, {"huhu", 43}};
  /* Incomplete bracing.  */
  struct U lu21 = {3, ls, 4, "huhu", 43};
  /* Optional braces around scalar initializers.  Accepted, but with
     a warning.  */
  struct U lu3 = { 3, {5,6,7,8,}, 4, {"huhu", 43}};
  /* Many superfluous braces and leaving out one initializer for U.s.c[1] */
  struct U lu4 = { 3, {5,6,7,},  5, { "bla", 44} };
  /* Superfluous braces and useless parens around values */
  struct S ls3 = { (1), (2), {(((3))), 4}};
  /* Superfluous braces, and leaving out braces for V.t, plus cast */
  struct V lv = {{3,4,{5,6}}, "haha", (u8)45, 46};
  /* Compound literal */
  struct V lv2 = {(struct S)w->t.s, {"hihi", 47}, 48};
  /* Parens around compound literal */
  struct V lv3 = {((struct S){7,8,{9,10}}), ((const struct W *)w)->t.t, 50};
  const struct pkthdr *phdr = phdr_;
  struct flowi6 flow = { .daddr = phdr->daddr, .saddr = phdr->saddr };
  int elt = 0x42;
  /* Range init, overlapping */
  struct T lt2 = { { [1 ... 5] = 9, [6 ... 10] = elt, [4 ... 7] = elt+1 }, 1 };
  print(ls);
  print(ls2);
  print(lt);
  print(lu);
  print(lu1);
  print(lu2);
  print(ls21);
  print(lu21);
  print(lu22);
  print(lu3);
  print(lu4);
  print(ls3);
  print(lv);
  print(lv2);
  print(lv3);
  print(lt2);
  print(flow);
}
#endif

void test_compound_with_relocs (void)
{
  struct Wrap local_wrap[] = {
      ((struct Wrap) {inc_global}),
      inc_global,
  };
  void (*p)(void);
  p = global_wrap[0].func; p();
  p = global_wrap[1].func; p();
  p = local_wrap[0].func; p();
  p = local_wrap[1].func; p();
}

void sys_ni(void) { printf("ni\n"); }
void sys_one(void) { printf("one\n"); }
void sys_two(void) { printf("two\n"); }
void sys_three(void) { printf("three\n"); }
typedef void (*fptr)(void);
const fptr table[3] = {
    [0 ... 2] = &sys_ni,
    [0] = sys_one,
    [1] = sys_two,
    [2] = sys_three,
};

void test_multi_relocs(void)
{
  int i;
  for (i = 0; i < sizeof(table)/sizeof(table[0]); i++)
    table[i]();
}

/* Following is from GCC gcc.c-torture/execute/20050613-1.c.  */

struct SEA { int i; int j; int k; int l; };
struct SEB { struct SEA a; int r[1]; };
struct SEC { struct SEA a; int r[0]; };
struct SED { struct SEA a; int r[]; };

static void
test_correct_filling (struct SEA *x)
{
  static int i;
  if (x->i != 0 || x->j != 5 || x->k != 0 || x->l != 0)
    printf("sea_fill%d: wrong\n", i);
  else
    printf("sea_fill%d: okay\n", i);
  i++;
}

int
test_zero_init (void)
{
  /* The peculiarity here is that only a.j is initialized.  That
     means that all other members must be zero initialized.  TCC
     once didn't do that for sub-level designators.  */
  struct SEB b = { .a.j = 5 };
  struct SEC c = { .a.j = 5 };
  struct SED d = { .a.j = 5 };
  test_correct_filling (&b.a);
  test_correct_filling (&c.a);
  test_correct_filling (&d.a);
  return 0;
}

int main()
{
  print(ce);
  print(gs);
  print(gs2);
  print(gt);
  print(gu);
  print(gu2);
  print(gu3);
  print(gu4);
  print(gs3);
  print(gv);
  print(gv2);
  print(gv3);
  print(sinit16);
  print(gw);
  print(gsu);
  print(guv);
  print(guv.b);
  print(guv2);
  print(guv3);
  print(phdr);
  foo(&gw, &phdr);
  //printf("q: %s\n", q);
  test_compound_with_relocs();
  test_multi_relocs();
  test_zero_init();
  return 0;
}
