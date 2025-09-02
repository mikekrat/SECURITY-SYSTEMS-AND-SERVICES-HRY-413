all: logger acmonitor test_aclog test_ac_monitor


logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 


acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor


test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog


run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

test_ac_monitor:
	./acmonitor -m                  # List malicious users
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file1.txt        # List users who modified 'file1.txt' and modification counts
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file2.txt        
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file3.txt        
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file4.txt        
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file5.txt        
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file6.txt        
	./acmonitor -i /home/mike/Desktop/sys_sec_2_2024/file7.txt        
	./acmonitor -h
	
clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
