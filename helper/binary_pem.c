#include <stdio.h>
#include <openssl/pem.h>

int main (int argc, char **argv) {
	if (argc < 2) {
		printf("usage: %s key.pem\n", argv[0]);
		exit(1);
	}

	FILE *fp = fopen(argv[1], "r");
	unsigned char *keydata = NULL;
	size_t kd_size, len;
	char *keyhash, *encodedhash;
	X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	kd_size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &keydata);
	int i;
	for (i = 0; i < kd_size - 1; i++) {
		printf("0x%x,", keydata[i]);
	}
	printf("0x%x\n", keydata[i]);
	printf("%d\n", kd_size);
	return 0;
}
