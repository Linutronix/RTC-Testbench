/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _NET_DEF_H_
#define _NET_DEF_H_

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>

#define ETH_P_PROFINET_RT (0x8892)
#ifndef ETH_P_LLDP
#define ETH_P_LLDP (0x88cc)
#endif
#ifndef ETH_P_OPCUA_PUBSUB
#define ETH_P_OPCUA_PUBSUB (0xb62c)
#endif
#ifndef ETH_P_AVTP
#define ETH_P_AVTP (0x22f0)
#endif
#ifndef ETH_P_ETHERCAT
#define ETH_P_ETHERCAT 0x88A4
#endif

#define VLAN_ID_MASK 0x0fff
#define VLAN_PCP_SHIFT 13

/* PROFINET VID values are predefined too. */
#define PROFINET_RT_VID_VALUE 0
#define TSN_LOW_VID_VALUE 0x102
#define TSN_HIGH_VID_VALUE 0x101

/* PROFINET PCP values are predefined. */
#define DCP_PCP_VALUE 2
#define RTA_PCP_VALUE 3
#define RTC_PCP_VALUE 4
#define TSN_LOW_PCP_VALUE 5
#define TSN_HIGH_PCP_VALUE 6

/* PROFINET FrameIds used by Testbench. */
#define TSN_HIGH_FRAMEID 0x0100
#define TSN_HIGH_SEC_FRAMEID 0x0101
#define TSN_LOW_FRAMEID 0x0200
#define TSN_LOW_SEC_FRAMEID 0x0201
#define RTC_FRAMEID 0x8000
#define RTC_SEC_FRAMEID 0x8001
#define RTA_FRAMEID 0xfc01
#define RTA_SEC_FRAMEID 0xfc02
#define DCP_FRAMEID 0xfefe

/* EtherCAT defines used by Testbench */
#define ETHERCAT_HEADER_LEN 2
#define ECAT_TX_TIMESTAMP_OFF 26
#define ECAT_LENGTH_OFF 14
#define ECAT_CMD_LENGTH_OFF 22

/* VLAN 802.1Q frame. */
struct vlan_ethernet_header {
	unsigned char destination[ETH_ALEN];
	unsigned char source[ETH_ALEN];
	__be16 vlan_proto;
	__be16 vlantci;
	__be16 vlan_encapsulated_proto;
} __attribute__((packed));

/* VLAN header. */
struct vlan_header {
	__be16 vlan_proto;
	__be16 vlantci;
} __attribute__((packed));

/* MetaData for testing, error checking and coordination. */
struct reference_meta_data {
	__be32 frame_counter;
	__be32 cycle_counter;
	__be64 tx_timestamp;
} __attribute__((packed));

/* PROFINET RT header. */
struct profinet_rt_header {
	__be16 frame_id;
	struct reference_meta_data meta_data;
} __attribute__((packed));

struct security_meta_data {
	/*
	 * Bit 0:   SecurityInformation.ProtectionMode
	 * Bit 1-7: Reserved
	 */
	__u8 security_information;
	/*
	 * Bit 0-3: NextContextID
	 * Bit 4-7: CurrentContextID
	 */
	__u8 security_control;
	/*
	 * Bit 0-31: SequenceCounter
	 */
	__be32 security_sequence_counter;
	/*
	 * Bit 0-10:  Length
	 * Bit 11-15: Reserved
	 */
	__be16 security_length;
} __attribute__((packed));

struct security_checksum {
	__u8 checksum[16];
} __attribute__((packed));

/* PROFINET Secure header. */
struct profinet_secure_header {
	__be16 frame_id;
	struct security_meta_data security_meta_data;
	struct reference_meta_data meta_data;
} __attribute__((packed));

/* Generic Layer 2 header. */
struct generic_l2_header {
	struct reference_meta_data meta_data;
} __attribute__((packed));

/* EtherCAT header */
struct ethercat_header {
	/*
	 * Bit 0-10 :  Length
	 * Bit 11   :  Reserved
	 * Bit 12-15:  Type: 0x1
	 */
	__be16 length;
} __attribute__((packed));

#endif /* _NET_DEF_H_ */
