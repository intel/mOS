#include <stdint.h>
#define NMC 6
#define NEDC 8
struct ctrs
{
    uint64_t mcrd[NMC];
    uint64_t mcwr[NMC];
    uint64_t edcrd[NEDC]; 
    uint64_t edcwr[NEDC];
    uint64_t edchite[NEDC];
    uint64_t edchitm[NEDC];
    uint64_t edcmisse[NEDC];
    uint64_t edcmissm[NEDC];
};
void readctrs(struct ctrs *c);
void setup(void);

