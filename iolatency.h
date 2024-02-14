#ifndef __IOLATENCY_H__
#define __IOLATENCY_H__

#define SLOTS 20

struct hist {
    __u32 slots[SLOTS];
};

#endif