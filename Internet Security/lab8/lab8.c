/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
BIGNUM* encrypt(BIGNUM *ciphertext,BIGNUM *message,BIGNUM *publickey,BIGNUM *theN){
	BN_CTX *ctx = BN_CTX_new();
	BN_mod_exp(ciphertext, message, publickey, theN, ctx);
	return ciphertext;
}
BIGNUM* decrypt(BIGNUM *message,BIGNUM *ciphertext,BIGNUM *privatekey,BIGNUM *theN){
	BN_CTX *ctx = BN_CTX_new();
	BN_mod_exp(message, ciphertext, privatekey, theN, ctx);
	return message;
}
int main ()
{	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *m1 = BN_new();
	BN_hex2bn(&m1,"ad16fa3193e7cbf66e744ddaec324ceb5faf24bf5c95aae7ea6e78c64dd29c7a");
	BIGNUM *s = BN_new();
	BN_hex2bn(&s,"38eb0b3f1aedc6b187bbe9cae50567f7e22811c4ed52ea7e9a607f75d8341a2a876d6a33a8131b376249e663fafc7e28e527dfc7f4f3446037668491a8379f4ddcb9f21747c627f2169772eb33e4f38d4a53109cde6b641c2967ca1b22d88ef0a18e8799601d0fac4a5a17fe3f270c309082b364706d80efc9d44fe57118610dc673e6a9a8cffceda1fe4834daa8dc9cfa23e849669bf02de5d59600d5f7ef8c92edcd1f80b659d667d9a08aa8a1a471b12265e51cf244d537073bf9099089086605a82dd14b6f10bd30a375eed332c010896919f7b20a95431775b1cc6a79bb2bce5a59c1b85a0f22b2bf5dd863d465881c51273c29f59868fe4cce8794eae8");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e,"010001");
	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"B2D805CA1C742DB5175639C54A520996E84BD80CF1689F9A422862C3A530537E5511825B037A0D2FE17904C9B496771981019459F9BCF77A9927822DB783DD5A277FB2037A9C5325E9481F464FC89D29F8BE7956F6F7FDD93A68DA8B4B82334112C3C83CCCD6967A84211A22040327178B1C6861930F0E5180331DB4B5CEEB7ED062ACEEB37B0174EF6935EBCAD53DA9EE9798CA8DAA440E25994A1596A4CE6D02541F2A6A26E2063A6348ACB44CD1759350FF132FD6DAE1C618F59FC9255DF3003ADE264DB42909CD0F3D236F164A8116FBF28310C3B8D6D855323DF1BD0FBD8C52954A16977A522163752F16F9C466BEF5B509D8FF2700CD447C6F4B3FB0F7");
	BIGNUM *ciphertext=BN_new();
	encrypt(ciphertext,s,e,n);
	printBN("This is the decoded message:", ciphertext);
	BIGNUM *reg= BN_new();
	BN_hex2bn(&reg,"10000000000000000000000000000000000000000000000000000000000000000");
	BN_mod(reg, ciphertext, reg, ctx);
	if(BN_cmp(reg,m1)==0){
		printf("Verify Success!!\n");
	}
	else{
		printf("Verify Denied!!\n");
	}
	/*
	BIGNUM *m1 = BN_new();
	BN_hex2bn(&m1,"4c61756e63682061206d697373696c652e");
	BIGNUM *s = BN_new();
	BN_hex2bn(&s,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e,"010001");
	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BIGNUM *ciphertext=BN_new();
	encrypt(ciphertext,s,e,n);
	printBN("This is the decoded message:", ciphertext);
	if(BN_cmp(ciphertext,m1)==0){
		printf("Verify Success!!\n");
	}
	else{
		printf("Verify Denied!!\n");
	}


/*
	BIGNUM *m1 = BN_new();
	BN_hex2bn(&m1,"49206f776520796f752024323030302e");
	BIGNUM *m2 = BN_new();
	BN_hex2bn(&m2,"49206f776520796f752024333030302e");

	BIGNUM *d = BN_new();
	BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e,"010001");
	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BIGNUM *ciphertext1=BN_new();
	encrypt(ciphertext1,m1,d,n);
	printBN("This is the sign of 2000 virsion: ",ciphertext1);
	
	BIGNUM *ciphertext2=BN_new();
	encrypt(ciphertext2,m2,d,n);
	printBN("This is the sign of 3000 virsion: ",ciphertext2);




/*
	BIGNUM *d = BN_new();
	BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e,"010001");
	BIGNUM *n = BN_new();
	BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BIGNUM *ciphertext=BN_new();
	encrypt(ciphertext,m,e,n);
	printBN("This is the ciphertext: ",ciphertext);
	BIGNUM *c = BN_new();
	BN_hex2bn(&c,"8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	BIGNUM *plaintext=BN_new();
	decrypt(plaintext,c,d,n);
	printBN("This is the plaintext decoded: ",plaintext);





BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *n = BN_new();
BIGNUM *d = BN_new();
BIGNUM *e = BN_new();
BIGNUM *res = BN_new();
BIGNUM *one = BN_new();
BIGNUM *zero = BN_new();

BIGNUM *reg1 = BN_new();
BIGNUM *reg2 = BN_new();
BIGNUM *reg3 = BN_new();
BIGNUM *reg4 = BN_new();
BIGNUM *reg5 = BN_new();


BN_one(one); 
BN_zero(zero);
BN_one(reg4);
// Initialize a, b, n
BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
BN_hex2bn(&e, "0D88C3");

BN_sub(reg1, p, one);
BN_sub(reg2, q, one);

BN_mul(reg3, reg1, reg2, ctx);
BN_mul(n, p, q, ctx);
BN_mod_inverse(d, n, reg3, ctx);
printBN("This is the private Key", d);
/*
while(1){
	BN_mul(reg1, d, e, ctx);
	BN_mod(reg2, reg1, reg3, ctx);
	if(BN_cmp(reg2,one)==0){
		printBN("This is the private Key", d);
		return 0;
	}
	else{
		BN_add(reg2,d,one);
		BN_copy(d,reg2);
	}
}

while(1){
	BN_add(reg1,reg3,one);	
	BN_mod(reg2, reg1, e, ctx);
	if(BN_cmp(reg2,zero)==0){
		BN_div(d, reg2, reg1,e,ctx);
		printBN("This is the private Key", d);
		return 0;
	}
	else{
		BN_add(reg4,reg4,one);
		BN_mul(reg3,reg3,reg4,ctx);
	}
}


/*
printBN("a * b = ", res);
// res = aˆb mod n
BN_mod_exp(res, a, b, n, ctx);
printBN("aˆc mod n = ", res);
*/
return 0;
}