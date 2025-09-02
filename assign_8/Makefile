Greeter: Greeter.c
	gcc -ansi -static -fno-stack-protector -z execstack -fno-pie -g -m32 Greeter.c -o Greeter
	gcc -z execstack -fno-stack-protector -m32 -o shellcode_test_program shellcode_test_program.c


secure_greeter: Greeter_secure.c
	gcc -ansi -fno-stack-protector -g -m32 Greeter_secure.c -o SecGreeter

clean:
	rm Greeter SecGreeter
