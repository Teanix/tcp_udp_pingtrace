#ifndef TCPPING_H
#define TCPPING_H

#define u64 unsigned long
#define u32 unsigned int
#define u16 unsigned short

struct durationTime {
	u64 dt1;
	u64 dt2;
	u64 dt3;
};

struct netInfoData {
	u64 pid;
	u64 time;
	u32 srcIP; 
	u32 dstIP;
	u16 srcPort;
	u16 dstPort;
	bool isdel;
	struct durationTime durationTime;
};


#endif