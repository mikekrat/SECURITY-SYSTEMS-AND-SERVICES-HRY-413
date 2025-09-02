Names: 1. Michail Kratimenos 2018030104
	   2. Georgios Piperakis 2018030012
Project Description:
		This project implements an access control logging and monitoring tool in Linux. We developed a shared library (logger.so) 
		that intercepts fopen and fwrite calls to log file access events, including denied access attempts. 
		The tool also includes a monitoring utility (acmonitor) that analyzes these logs, identifying unauthorized access and tracking file modifications.
Important Notes:
		1.We have provided you with some extra login data in file_logging_history.log file, which provides more detailed examples of logins with action from more users.
		  To use it rename it into file_logging.log and if you use it mind not to execute 'make run' in terminal, as it will overwrite it. Execute immediately 'make all'
		2.In order to execute efficiently test_fwrite in test_aclog, you need to execute test_aclog as administrator (sudo LD_PRELOAD=./logger.so ./test_aclog)
		3.We have updated the makefile, in order to contain tests for ac_monitor