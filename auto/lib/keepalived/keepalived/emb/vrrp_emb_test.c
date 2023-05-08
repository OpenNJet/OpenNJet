/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "vrrp_emb.h"


static void
stop_vrrp( __attribute__((unused)) int sig)
{
	fprintf(stderr,"signal stop\n");
	vrrp_emb_stop();
}

static  void
vrrp_signal_reg(void)
{
	fprintf(stderr,"reg signals in %d, %d,%d,%d,%p\n",getpid(),SIGHUP,SIGINT,SIGTERM,stop_vrrp);
	signal(SIGINT, stop_vrrp);
	signal(SIGHUP, stop_vrrp);
	signal(SIGTERM, stop_vrrp);
    //signal_set(SIGHUP, stop_vrrp, NULL);
    //signal_set(SIGINT, stop_vrrp, NULL);
    //signal_set(SIGTERM, stop_vrrp, NULL);
}


void printUsage(const char *progName){
	fprintf(stdout,
"HA test program, forked from keepalived, copyRight by stdanley@gmail.com\n"
"\n"
"Usage %s <-c cfgFile> <-l logfileName>\n"
"exam: %s -c ./vrrp.cfg -l /home/pi/keepalived/v2/out.log\n"
"\n"
"the cfgFile is  syntax complied with the keepalived cfg\n"
"the logFile name is the log target ,it must be noted it has to be absolute path, i.e., start with /\n"
,progName,progName);
}
int main(int argc, char **argv){
	char c;
	const char  *cfg=NULL, *log=NULL;
	while ((c = getopt (argc, argv, "c:l:h")) != -1)
        switch (c) {
        case 'c':
                cfg = optarg;break;
        case 'l':
                log = optarg;break;
		case '?':
			if (optopt == 'c') fprintf(stderr,"Option -%c require vrrp cfg file\n",optopt);	
			else if (optopt == 'n') fprintf(stderr,"Option -%c require log file name\n",optopt);	
			else
                fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            return 1;
		case 'h':
        default:	
			printUsage(argv[0]);
			return 0;
	}
	if (!cfg || !log) {
		printUsage(argv[0]);
		return 1;
	}
	int ret=vrrp_emb_init(cfg,log);
	if (ret) {
		fprintf(stderr,"init vrrp failed\n");
		return 2;
	}
		vrrp_signal_reg();
		vrrp_emb_run();
}

