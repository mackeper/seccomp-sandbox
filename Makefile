COMPILER = gcc
FLAGS = -lseccomp

all: main

sandbox: sandbox.c
	$(COMPILER) sandbox.c $(FLAGS) -o sandbox

safe-test:
	$(COMPILER) safe-test.c -o safe-test

malware-test:
	$(COMPILER) malware-test.c -o malware-test

main: sandbox safe-test malware-test

clean:
	rm sandbox
	rm safe-test
	rm malware-test
