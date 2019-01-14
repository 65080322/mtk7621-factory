#ifndef __FACTORY_TEST_H__
#define __FACTORY_TEST_H__

int default_age_time = 12*60*60;
int default_err_count = 1000;

const char version[] = "V2.0-20190114";
//#define ARMADA
//const char board_name[] = "NM01";
//const char if_name[17][5] = {"lan0", "lan1", "lan2", "lan3", "lan4", "\0"};
#define MTK
const char board_name[] = "NA20";
const char if_name[17][7]= {"eth0.1", "eth0.2", "eth0.3", "eth0.4", "eth0.5", "eth1", "\0"};
const char REVERSION[] = "LE11B05SIM7600M21";

//const char if_name[17][5] = {"eth0", "\0"};
#define MAX_DATA    64
#define ETH_P_DEAN 0x8874


#endif
