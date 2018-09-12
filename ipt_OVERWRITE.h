/* Arbitrary overwrite modification module for IP tables
   Defines data structure that is passed from userland
   to the kernel
 */

#ifndef _IPT_OVERWRiTE_H
#define _IPT_OVERWRITE_H
#include <linux/types.h>


#define IPT_STRING_MAX_PATTERN_SIZE 128

enum {
	IPT_OVERWRITE_STR = 0x01,
	IPT_OVERWRITE_HEX = 0x02
};

enum {
	IPT_CSUM_NO_OFFLOAD = 0x00,
	IPT_CSUM_OFFLOAD = 0x01
};

struct ipt_OVERWRITE_info {
	__u16	offset;
	char	pattern[IPT_STRING_MAX_PATTERN_SIZE];
	__u8	patlen; 
	__u8	offload;
	__u8 	flags;

	struct ts_config __attribute__((aligned(8))) *config;
};

#endif
