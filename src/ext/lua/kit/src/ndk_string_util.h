

#define     ndk_str_init(ns,s)              {(ns).data = (u_char*) s; (ns).len = sizeof (s) - 1;}
#define     ndk_strp_init(ns,s)             {(ns)->data = (u_char*) s; (ns)->len = sizeof (s) - 1;}

#define     ndk_zero(p,sz)                  memset (p,'\0',sz)
#define     ndk_zerop(p)                    ndk_zero (p,sizeof(*p))
#define     ndk_zeropn(p,n)                 ndk_zero (p,sizeof(*p)*(n))
#define     ndk_zerov(v)                    ndk_zero (&v,sizeof(v))

#define     njt_null_enum   { njt_null_string, 0 }

#define     ndk_memcpyp(d,s)                njt_memcpy(d,s,sizeof(*s))

