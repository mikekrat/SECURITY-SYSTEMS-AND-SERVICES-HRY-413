output: 
	gcc -o rsa_assign_1 rsa_assign_1.c -lgmp
	./rsa_assign_1 -g 1024
	./rsa_assign_1 -i plaintext.txt -o ciphertext.txt -k public_1024.key -e
	./rsa_assign_1 -i ciphertext.txt -o output.txt -k private_1024.key -d 
	./rsa_assign_1 -a performance.txt

clean:
	rm rsa_assign_1 ciphertext.txt decrypted.txt output.txt private_1024.key public_1024.key private_2048.key public_2048.key private_4096.key public_4096.key