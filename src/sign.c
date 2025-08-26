

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>


static const uint64_t keccakf_rndc[24] = {
 0x00000001U,0x00008082U,0x0000808aU,0x80008000U,0x0000808bU,0x80000001U,0x80008081U,0x00008009U,
 0x0000008aU,0x00000088U,0x80008009U,0x8000000aU,0x8000808bU,0x0000008bU,0x00008089U,0x00008003U,
 0x00008002U,0x00000080U,0x0000800aU,0x8000000aU,0x80008081U,0x00008080U,0x80000001U,0x80008008U
};
static const int keccakf_rotc[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int keccakf_piln[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

static void keccakf(uint64_t st[25]) {
    for (int r=0;r<24;r++){
        uint64_t bc[5];
        for (int i=0;i<5;i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i=0;i<5;i++){
            uint64_t t = bc[(i+4)%5] ^ ((bc[(i+1)%5] << 1) | (bc[(i+1)%5] >> 63));
            for (int j=0;j<25;j+=5) st[j+i] ^= t;
        }
        uint64_t t = st[1];
        for (int i=0;i<24;i++){
            int j = keccakf_piln[i];
            uint64_t tmp = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = tmp;
        }
        for (int j=0;j<25;j+=5){
            uint64_t tmp[5];
            for (int i=0;i<5;i++) tmp[i] = st[j+i];
            for (int i=0;i<5;i++) st[j+i] ^= (~tmp[(i+1)%5]) & tmp[(i+2)%5];
        }
        st[0] ^= keccakf_rndc[r];
    }
}

static void keccak256(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint64_t st[25] = {0};
    uint8_t temp[200] = {0};
    size_t mdlen = 32;
    size_t rsiz = 200 - 2*mdlen;

    size_t offset = 0;
    while (inlen >= rsiz) {
        for (size_t i=0;i<rsiz;i++) temp[i] = in[offset+i];
        for (size_t i=0;i<rsiz/8;i++) {
            uint64_t t = 0;
            for (int b=0;b<8;b++) t |= (uint64_t)temp[i*8+b] << (8*b);
            st[i] ^= t;
        }
        keccakf(st);
        inlen -= rsiz;
        offset += rsiz;
    }
    // Remaining input
    memset(temp,0,sizeof(temp));
    memcpy(temp,in+offset,inlen);
    temp[inlen++] = 1;
    temp[rsiz-1] |= 0x80;
    for (size_t i=0;i<rsiz/8;i++) {
        uint64_t t = 0;
        for (int b=0;b<8;b++) t |= (uint64_t)temp[i*8+b] << (8*b);
        st[i] ^= t;
    }
    keccakf(st);
    for (size_t i=0;i<mdlen;i++) out[i] = ((uint8_t*)st)[i];
}


static int hexchar2int(char c){
    if ('0'<=c && c<='9') return c-'0';
    if ('a'<=c && c<='f') return c-'a'+10;
    if ('A'<=c && c<='F') return c-'A'+10;
    return -1;
}

static int hex2bin(const char *hex, unsigned char *out, size_t outlen){
    if (!hex) return -1;
    const char *p = hex;
    size_t hlen = strlen(hex);
    if (hlen >= 2 && hex[0]=='0' && (hex[1]=='x' || hex[1]=='X')) { p += 2; hlen -= 2; }
    if (hlen % 2) return -1;
    if (outlen < hlen/2) return -1;
    for (size_t i=0;i<hlen/2;i++){
        int hi = hexchar2int(p[2*i]), lo = hexchar2int(p[2*i+1]);
        if (hi<0 || lo<0) return -1;
        out[i] = (hi<<4) | lo;
    }
    return (int)(hlen/2);
}

static void bin2hex(const unsigned char *bin, size_t len, char *out){
    static const char hex[] = "0123456789abcdef";
    for (size_t i=0;i<len;i++){
        out[2*i] = hex[(bin[i]>>4)&0xF];
        out[2*i+1] = hex[bin[i]&0xF];
    }
    out[2*len] = 0;
}


typedef struct { unsigned char *buf; size_t len, cap; } dynbuf;
static void db_init(dynbuf *d){ d->buf=NULL; d->len=d->cap=0; }
static void db_free(dynbuf *d){ free(d->buf); d->buf=NULL; d->len=d->cap=0; }
static int db_ensure(dynbuf *d,size_t n){
    if (d->len+n <= d->cap) return 0;
    size_t nc = d->cap?d->cap*2:512;
    while (nc < d->len+n) nc*=2;
    unsigned char *p = realloc(d->buf,nc);
    if (!p) return -1;
    d->buf=p; d->cap=nc; return 0;
}
static int db_append(dynbuf *d,const unsigned char *p,size_t n){
    if(db_ensure(d,n)) return -1;
    memcpy(d->buf+d->len,p,n); d->len+=n; return 0;
}


static int rlp_encode_length(dynbuf *d, unsigned long len, unsigned char offset_short, unsigned char offset_long){
    if(len <= 55) { unsigned char b = offset_short + (unsigned char)len; return db_append(d,&b,1); }
    unsigned char tmp[16]; int t=0;
    while(len){ tmp[t++] = len & 0xff; len >>= 8; }
    unsigned char first = offset_long + t;
    if(db_append(d,&first,1)) return -1;
    for(int i=t-1;i>=0;i--) if(db_append(d,&tmp[i],1)) return -1;
    return 0;
}

static int rlp_encode_bytes(dynbuf *d,const unsigned char *data,size_t len){
    if(len==1 && data[0]<=0x7f) return db_append(d,data,1);
    if(rlp_encode_length(d,len,0x80,0xb7)) return -1;
    return db_append(d,data,len);
}


static int rlp_encode_integer_from_decstr(dynbuf *d,const char *decstr){
    if(!decstr || strcmp(decstr,"0")==0){ unsigned char z=0x80; return db_append(d,&z,1); }
    size_t slen=strlen(decstr);
    unsigned char *digits=malloc(slen);
    if(!digits) return -1;
    for(size_t i=0;i<slen;i++){ if(!isdigit((unsigned char)decstr[i])) { free(digits); return -1; } digits[i]=decstr[i]-'0'; }
    unsigned char outbuf[1024]; size_t outlen=0;
    while(1){
        int carry=0; int allzero=1;
        for(size_t i=0;i<slen;i++){
            int v=digits[i]+carry*10;
            digits[i]=v/256;
            carry=v%256;
            if(digits[i]) allzero=0;
        }
        outbuf[outlen++]=(unsigned char)carry;
        if(allzero) break;
    }
    free(digits);
    while(outlen>0 && outbuf[outlen-1]==0) outlen--;
    unsigned char be[1024];
    for(size_t i=0;i<outlen;i++) be[i]=outbuf[outlen-1-i];
    return rlp_encode_bytes(d,be,outlen);
}


static int rlp_encode_list_from_buf(dynbuf *d,const unsigned char *buf,size_t buflen){
    return rlp_encode_length(d,buflen,0xc0,0xf7) ? -1 : db_append(d,buf,buflen);
}


static int read_privkey_from_wallet(unsigned char out_priv[32]){
    const char *home = getenv("HOME");
    if(!home) return -1;
    char path[1024]; snprintf(path,sizeof(path),"%s/.gorilla_wallets/wallet.dat",home);
    FILE *f = fopen(path,"r"); if(!f) return -1;
    char line[1024], keyhex[130]={0};
    while(fgets(line,sizeof(line),f)){
        if(strstr(line,"private_key")){
            char *q=strchr(line,'"'); if(!q) continue;
            q=strchr(q+1,'"'); if(!q) continue;
            q=strchr(q+1,'"'); if(!q) continue; q++;
            char *r=strchr(q,'"'); if(!r) continue;
            size_t len=r-q; if(len>=sizeof(keyhex)) len=sizeof(keyhex)-1;
            strncpy(keyhex,q,len); keyhex[len]=0;
            break;
        }
    }
    fclose(f);
    if(!keyhex[0]) return -1;
    if(keyhex[0]=='0' && (keyhex[1]=='x'||keyhex[1]=='X')) memmove(keyhex,keyhex+2,strlen(keyhex)-1);
    if(hex2bin(keyhex,out_priv,32)!=32) return -1;
    return 0;
}


static const unsigned char SECP256K1_ORDER[32]={
 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
 0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
};
static const unsigned char SECP256K1_HALF_ORDER[32]={
 0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
 0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
};

static int be32_gt(const unsigned char a[32], const unsigned char b[32]){
    for(int i=0;i<32;i++){ if(a[i]>b[i]) return 1; if(a[i]<b[i]) return 0; }
    return 0;
}
static void be32_sub_order(const unsigned char s[32],unsigned char out[32]){
    unsigned int borrow=0;
    for(int i=31;i>=0;i--){
        unsigned int ord=SECP256K1_ORDER[i];
        unsigned int si=s[i];
        unsigned int sub=ord-si-borrow;
        out[i]=(unsigned char)(sub&0xff);
        borrow=(si+borrow>ord)?1:0;
    }
}


static const char *strip0x(const char *s){ return (s && s[0]=='0' && (s[1]=='x'||s[1]=='X'))?s+2:s; }
static unsigned long parse_ulong(const char *s){ char *end; unsigned long v=strtoul(s,&end,10); return (end==s)?0:v; }


static int build_signing_rlp(
    const char *nonce,const char *gasPrice,const char *gasLimit,
    const unsigned char *to,size_t to_len,
    const char *value,const unsigned char *data,size_t data_len,
    unsigned long chainId,dynbuf *out_rlp)
{
    dynbuf tmp; db_init(&tmp);
    if(rlp_encode_integer_from_decstr(&tmp,nonce)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,gasPrice)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,gasLimit)) goto err;
    if(to_len==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; }
    else if(rlp_encode_bytes(&tmp,to,to_len)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,value)) goto err;
    if(data_len==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; }
    else if(rlp_encode_bytes(&tmp,data,data_len)) goto err;
    char chaindec[32]; snprintf(chaindec,sizeof(chaindec),"%lu",chainId);
    if(rlp_encode_integer_from_decstr(&tmp,chaindec)) goto err;
    unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; if(db_append(&tmp,&z,1)) goto err;
    if(rlp_encode_list_from_buf(out_rlp,tmp.buf,tmp.len)) goto err;
    db_free(&tmp); return 0;
err: db_free(&tmp); return -1;
}


static int build_signed_rlp(
    const char *nonce,const char *gasPrice,const char *gasLimit,
    const unsigned char *to,size_t to_len,
    const char *value,const unsigned char *data,size_t data_len,
    unsigned long v,const unsigned char *r,size_t rlen,const unsigned char *s,size_t slen,
    dynbuf *out_rlp)
{
    dynbuf tmp; db_init(&tmp);
    if(rlp_encode_integer_from_decstr(&tmp,nonce)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,gasPrice)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,gasLimit)) goto err;
    if(to_len==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; }
    else if(rlp_encode_bytes(&tmp,to,to_len)) goto err;
    if(rlp_encode_integer_from_decstr(&tmp,value)) goto err;
    if(data_len==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; }
    else if(rlp_encode_bytes(&tmp,data,data_len)) goto err;
    char vdec[32]; snprintf(vdec,sizeof(vdec),"%lu",v);
    if(rlp_encode_integer_from_decstr(&tmp,vdec)) goto err;

    size_t rtrim=rlen; while(rtrim>0 && r[rlen-rtrim]==0) rtrim--;
    if(rtrim==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; } 
    else if(rlp_encode_bytes(&tmp,r+(rlen-rtrim),rtrim)) goto err;

    size_t strim=slen; while(strim>0 && s[slen-strim]==0) strim--;
    if(strim==0){ unsigned char z=0x80; if(db_append(&tmp,&z,1)) goto err; } 
    else if(rlp_encode_bytes(&tmp,s+(slen-strim),strim)) goto err;

    if(rlp_encode_list_from_buf(out_rlp,tmp.buf,tmp.len)) goto err;
    db_free(&tmp); return 0;
err: db_free(&tmp); return -1;
}


int main(int argc,char **argv){
    if(argc<8){ fprintf(stderr,"Usage: %s <nonce> <gasPrice> <gasLimit> <to_hex_or_empty> <value> <data_hex_or_empty> <chainId>\n",argv[0]); return 1; }

    const char *nonce=argv[1],*gasPrice=argv[2],*gasLimit=argv[3];
    const char *to_hex=argv[4],*value=argv[5],*data_hex=argv[6];
    unsigned long chainId=parse_ulong(argv[7]);

    unsigned char privkey[32];
    if(read_privkey_from_wallet(privkey)!=0){ fprintf(stderr,"Failed to read private key\n"); return 1; }

    unsigned char to_bin[20]; size_t to_len=0;
    if(to_hex && *to_hex){
        const char *s=strip0x(to_hex);
        if(strlen(s)!=40){ fprintf(stderr,"Invalid to address length\n"); return 1; }
        if(hex2bin(s,to_bin,sizeof(to_bin))!=20){ fprintf(stderr,"Invalid to address hex\n"); return 1; }
        to_len=20;
    }

    unsigned char *data_bin=NULL; size_t data_len=0;
    if(data_hex && *data_hex){
        const char *s=strip0x(data_hex);
        size_t slen=strlen(s);
        if(slen%2){ fprintf(stderr,"Data hex must be even\n"); return 1; }
        data_len=slen/2;
        data_bin=malloc(data_len);
        if(!data_bin){ fprintf(stderr,"OOM\n"); return 1; }
        if(hex2bin(s,data_bin,data_len)!=(int)data_len){ fprintf(stderr,"Invalid data hex\n"); free(data_bin); return 1; }
    }

    dynbuf sign_rlp; db_init(&sign_rlp);
    if(build_signing_rlp(nonce,gasPrice,gasLimit,(to_len?to_bin:NULL),to_len,value,(data_len?data_bin:NULL),data_len,chainId,&sign_rlp)!=0){
        fprintf(stderr,"Failed to build signing RLP\n"); db_free(&sign_rlp); free(data_bin); return 1;
    }

    uint8_t hash[32]; keccak256(sign_rlp.buf,sign_rlp.len,hash);

    secp256k1_context *ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_recoverable_signature rsig;
    if(!secp256k1_ecdsa_sign_recoverable(ctx,&rsig,hash,privkey,NULL,NULL)){
        fprintf(stderr,"Signing failed\n"); db_free(&sign_rlp); free(data_bin); secp256k1_context_destroy(ctx); return 1;
    }

    unsigned char sig64[64]; int recid=0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,sig64,&recid,&rsig);

    unsigned char r[32],s[32]; memcpy(r,sig64,32); memcpy(s,sig64+32,32);

    if(be32_gt(s,SECP256K1_HALF_ORDER)){ unsigned char snew[32]; be32_sub_order(s,snew); memcpy(s,snew,32); recid^=1; }

    unsigned long v=(unsigned long)recid+35+2*chainId;

    dynbuf signed_rlp; db_init(&signed_rlp);
    if(build_signed_rlp(nonce,gasPrice,gasLimit,(to_len?to_bin:NULL),to_len,value,(data_len?data_bin:NULL),data_len,v,r,sizeof(r),s,sizeof(s),&signed_rlp)!=0){
        fprintf(stderr,"Failed to build signed RLP\n"); db_free(&sign_rlp); db_free(&signed_rlp); free(data_bin); secp256k1_context_destroy(ctx); return 1;
    }

    char *hexdump=malloc(signed_rlp.len*2+1);
    if(!hexdump){ fprintf(stderr,"OOM\n"); return 1; }
    bin2hex(signed_rlp.buf,signed_rlp.len,hexdump);
    printf("rawtx: 0x%s\n",hexdump);

    free(hexdump); db_free(&sign_rlp); db_free(&signed_rlp); free(data_bin); secp256k1_context_destroy(ctx);
    return 0;
}
