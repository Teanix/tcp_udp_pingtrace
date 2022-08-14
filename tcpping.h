#ifndef TCPPING_H
#define TCPPING_H

#define u64 unsigned long
#define u32 uint32_t
#define u16 unsigned short

struct durationTime {
	u64 dt1;
	u64 dt2;
	u64 dt3;
	u64 dt4;
	u64 dt5;
	u64 dt6;
	u64 dt7;
};

struct tuple{
	u32 srcIP;
	u32 dstIP;
	u16 srcPort;
	u16 dstPort; 
};

struct net_time_Info {
	u64 pid;
	u64 time;
	bool isdel;
	struct tuple tuple;
	struct durationTime durationTime;
};

#endif