// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026 Linutronix GmbH
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "config.h"
#include "stat.h"
#include "utils.h"

/*
 * config.c references a few print/name helpers from the rest of the code base
 * (only from the config_print_*() path, which is not exercised here). Provide
 * minimal stubs so the parser can be tested in isolation.
 */
const char *stat_frame_type_names[NUM_FRAME_TYPES];

void print_payload_pattern(const char __unused *payload_pattern,
			   size_t __unused payload_pattern_length)
{
}

void print_mac_address(const unsigned char __unused *mac_address)
{
}

void print_cpu_list(const int __unused *cpus, size_t __unused cpus_len)
{
}

void print_clockid(clockid_t __unused clock)
{
}

/*
 * Write the given YAML string to a temporary file, feed it to
 * config_read_from_file() and return its result.
 */
static int load_config(const char *yaml)
{
	char path[] = "/tmp/rtc_config_test_XXXXXX";
	ssize_t written;
	int fd, ret;
	size_t len;

	fd = mkstemp(path);
	assert_true(fd >= 0);

	len = strlen(yaml);
	written = write(fd, yaml, len);
	assert_int_equal(written, (ssize_t)len);
	close(fd);

	ret = config_read_from_file(path);

	unlink(path);

	return ret;
}

/* Reset the global configuration before every test. */
static int setup(void __unused **state)
{
	memset(&app_config, 0, sizeof(app_config));
	return 0;
}

/* Release all strings the parser may have allocated. */
static int teardown(void __unused **state)
{
	config_free();
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Data type parsing - one test per config_value_type                        */
/* ------------------------------------------------------------------------- */

static void test_type_bool(void __unused **state)
{
	assert_int_equal(load_config("TsnHighEnabled: true\n"), 0);
	assert_true(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);

	assert_int_equal(load_config("TsnHighEnabled: false\n"), 0);
	assert_false(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);

	/* "1" / "0" are valid as well */
	assert_int_equal(load_config("TsnHighEnabled: 1\n"), 0);
	assert_true(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);

	assert_int_equal(load_config("TsnHighEnabled: 0\n"), 0);
	assert_false(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);

	/* Parsing is case insensitive */
	assert_int_equal(load_config("TsnHighEnabled: TRUE\n"), 0);
	assert_true(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);
}

static void test_type_int(void __unused **state)
{
	assert_int_equal(load_config("TsnHighVid: 100\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].vid, 100);

	/* Negative integers are accepted (e.g. thread priorities/cpus) */
	assert_int_equal(load_config("LogThreadCpu: -1\n"), 0);
	assert_int_equal(app_config.log_thread_cpu, -1);
}

static void test_type_ulong(void __unused **state)
{
	assert_int_equal(load_config("TsnHighRxWorkloadSkipCount: 123456\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].rx_workload_skip_count, 123456);
}

static void test_type_size(void __unused **state)
{
	assert_int_equal(load_config("TsnHighNumFramesPerCycle: 32\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].num_frames_per_cycle, 32);
}

static void test_type_time(void __unused **state)
{
	/* Plain nanoseconds */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: 1000\n"), 0);
	assert_int_equal(app_config.application_base_cycle_time_ns, 1000);

	/* Seconds */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: 1s\n"), 0);
	assert_int_equal(app_config.application_base_cycle_time_ns, 1000000000ULL);

	/* Milliseconds */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: 1ms\n"), 0);
	assert_int_equal(app_config.application_base_cycle_time_ns, 1000000ULL);

	/* Microseconds */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: 5us\n"), 0);
	assert_int_equal(app_config.application_base_cycle_time_ns, 5000ULL);
}

static void test_type_string(void __unused **state)
{
	assert_int_equal(load_config("LogLevel: Debug\n"), 0);
	assert_non_null(app_config.log_level);
	assert_string_equal(app_config.log_level, "Debug");
	assert_int_equal(app_config.log_level_length, strlen("Debug"));
}

static void test_type_payload(void __unused **state)
{
	assert_int_equal(load_config("TsnHighPayloadPattern: Hello\n"), 0);
	assert_non_null(app_config.classes[TSN_HIGH_FRAME_TYPE].payload_pattern);
	assert_string_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].payload_pattern, "Hello");
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].payload_pattern_length,
			 strlen("Hello"));
}

static void test_type_interface(void __unused **state)
{
	assert_int_equal(load_config("TsnHighInterface: enp3s0\n"), 0);
	assert_string_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].interface, "enp3s0");
}

static void test_type_interface_truncation(void __unused **state)
{
	char expected[IF_NAMESIZE];
	char yaml[128];

	/* An overly long interface name is truncated to IF_NAMESIZE - 1. */
	snprintf(yaml, sizeof(yaml),
		 "TsnHighInterface: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
	memset(expected, 'a', sizeof(expected));
	expected[IF_NAMESIZE - 1] = '\0';

	assert_int_equal(load_config(yaml), 0);
	assert_string_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].interface, expected);
}

static void test_type_mac(void __unused **state)
{
	const unsigned char expected[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

	assert_int_equal(load_config("DebugMonitorDestination: aa:bb:cc:dd:ee:ff\n"), 0);
	assert_memory_equal(app_config.debug_monitor_destination, expected, ETH_ALEN);
}

static void test_type_ether_type(void __unused **state)
{
	/* EtherType is parsed as hexadecimal. */
	assert_int_equal(load_config("GenericL2EtherType: 88f7\n"), 0);
	assert_int_equal(app_config.classes[GENERICL2_FRAME_TYPE].ether_type, 0x88f7);

	assert_int_equal(load_config("GenericL2EtherType: 0xb62c\n"), 0);
	assert_int_equal(app_config.classes[GENERICL2_FRAME_TYPE].ether_type, 0xb62c);
}

static void test_type_security_mode(void __unused **state)
{
	assert_int_equal(load_config("TsnHighSecurityMode: none\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode, SECURITY_MODE_NONE);

	assert_int_equal(load_config("TsnHighSecurityMode: ao\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode, SECURITY_MODE_AO);

	assert_int_equal(load_config("TsnHighSecurityMode: AE\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode, SECURITY_MODE_AE);
}

static void test_type_security_algorithm(void __unused **state)
{
	assert_int_equal(load_config("TsnHighSecurityAlgorithm: aes256-gcm\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_algorithm,
			 SECURITY_ALGORITHM_AES256_GCM);

	assert_int_equal(load_config("TsnHighSecurityAlgorithm: aes128-gcm\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_algorithm,
			 SECURITY_ALGORITHM_AES128_GCM);

	assert_int_equal(load_config("TsnHighSecurityAlgorithm: chacha20-poly1305\n"), 0);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].security_algorithm,
			 SECURITY_ALGORITHM_CHACHA20_POLY1305);
}

static void test_type_cpu_list(void __unused **state)
{
	const struct traffic_class_config *conf = &app_config.classes[TSN_HIGH_FRAME_TYPE];

	/* Comma separated */
	assert_int_equal(load_config("TsnHighRxWorkloadThreadCpu: 1,2,3\n"), 0);
	assert_int_equal(conf->workload_thread_cpus_num, 3);
	assert_int_equal(conf->workload_thread_cpus[0], 1);
	assert_int_equal(conf->workload_thread_cpus[1], 2);
	assert_int_equal(conf->workload_thread_cpus[2], 3);

	/* Space separated */
	assert_int_equal(load_config("TsnHighRxWorkloadThreadCpu: 0 2 4\n"), 0);
	assert_int_equal(conf->workload_thread_cpus_num, 3);
	assert_int_equal(conf->workload_thread_cpus[0], 0);
	assert_int_equal(conf->workload_thread_cpus[1], 2);
	assert_int_equal(conf->workload_thread_cpus[2], 4);
}

static void test_type_clockid(void __unused **state)
{
	assert_int_equal(load_config("ApplicationClockId: CLOCK_TAI\n"), 0);
	assert_int_equal(app_config.application_clock_id, CLOCK_TAI);

	assert_int_equal(load_config("ApplicationClockId: CLOCK_MONOTONIC\n"), 0);
	assert_int_equal(app_config.application_clock_id, CLOCK_MONOTONIC);

	assert_int_equal(load_config("ApplicationClockId: CLOCK_REALTIME\n"), 0);
	assert_int_equal(app_config.application_clock_id, CLOCK_REALTIME);

	/*
	 * CLOCK_AUX<n> requires a valid base start time, otherwise the parser
	 * tries to query the (usually unconfigured) aux clock at the end.
	 */
	assert_int_equal(
		load_config("ApplicationBaseStartTimeNS: 5\nApplicationClockId: CLOCK_AUX0\n"), 0);
	assert_int_equal(app_config.application_clock_id, CLOCK_AUX + 0);
}

static void test_type_protocol_type(void __unused **state)
{
	assert_int_equal(load_config("GenericL2ProtocolType: L2\n"), 0);
	assert_int_equal(app_config.classes[GENERICL2_FRAME_TYPE].protocol_type,
			 GENERICL2_PROTOCOL_TYPE);

	assert_int_equal(load_config("GenericL2ProtocolType: EtherCAT\n"), 0);
	assert_int_equal(app_config.classes[GENERICL2_FRAME_TYPE].protocol_type,
			 ETHERCAT_PROTOCOL_TYPE);
}

/* ------------------------------------------------------------------------- */
/* Invalid values - one test per data type                                   */
/* ------------------------------------------------------------------------- */

static void test_invalid_bool(void __unused **state)
{
	assert_int_equal(load_config("TsnHighEnabled: maybe\n"), -EINVAL);
}

static void test_invalid_int(void __unused **state)
{
	assert_int_equal(load_config("TsnHighVid: notanumber\n"), -EINVAL);
	/* Trailing garbage is rejected */
	assert_int_equal(load_config("TsnHighVid: 100abc\n"), -EINVAL);
}

static void test_invalid_ulong(void __unused **state)
{
	assert_int_equal(load_config("TsnHighRxWorkloadSkipCount: foo\n"), -EINVAL);
}

static void test_invalid_time(void __unused **state)
{
	/* Unknown unit */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: 5x\n"), -EINVAL);
	/* Not a number at all */
	assert_int_equal(load_config("ApplicationBaseCycleTimeNS: abc\n"), -EINVAL);
}

static void test_invalid_mac(void __unused **state)
{
	assert_int_equal(load_config("DebugMonitorDestination: zz:zz:zz:zz:zz:zz\n"), -EINVAL);
	assert_int_equal(load_config("DebugMonitorDestination: 11:22:33\n"), -EINVAL);
}

static void test_invalid_ether_type(void __unused **state)
{
	assert_int_equal(load_config("GenericL2EtherType: nothex\n"), -EINVAL);
}

static void test_invalid_security_mode(void __unused **state)
{
	assert_int_equal(load_config("TsnHighSecurityMode: bogus\n"), -EINVAL);
}

static void test_invalid_security_algorithm(void __unused **state)
{
	assert_int_equal(load_config("TsnHighSecurityAlgorithm: bogus\n"), -EINVAL);
}

static void test_invalid_cpu_list(void __unused **state)
{
	/* Negative CPUs are rejected */
	assert_int_equal(load_config("TsnHighRxWorkloadThreadCpu: -1\n"), -EINVAL);
}

static void test_invalid_clockid(void __unused **state)
{
	assert_int_equal(load_config("ApplicationClockId: CLOCK_FOO\n"), -EINVAL);
	/* Out of range aux clock */
	assert_int_equal(load_config("ApplicationClockId: CLOCK_AUX999\n"), -EINVAL);
}

static void test_invalid_protocol_type(void __unused **state)
{
	assert_int_equal(load_config("GenericL2ProtocolType: bogus\n"), -EINVAL);
}

/* ------------------------------------------------------------------------- */
/* Structural / file level errors                                            */
/* ------------------------------------------------------------------------- */

static void test_unknown_global_option(void __unused **state)
{
	assert_int_equal(load_config("ThisOptionDoesNotExist: 42\n"), -ENOENT);
}

static void test_unknown_class_option(void __unused **state)
{
	/* Valid traffic class prefix, but unknown suffix */
	assert_int_equal(load_config("TsnHighNoSuchThing: 1\n"), -ENOENT);
}

static void test_option_on_wrong_traffic_class(void __unused **state)
{
	/*
	 * XdpEnabled is only valid for XDP capable traffic classes. DCP is not
	 * one of them, hence this must be rejected as unknown.
	 */
	assert_int_equal(load_config("DcpXdpEnabled: true\n"), -ENOENT);
}

static void test_malformed_yaml(void __unused **state)
{
	/* Unterminated quoted scalar -> libyaml scanner error */
	assert_int_equal(load_config("TsnHighVid: \"unterminated\n"), -EINVAL);
}

static void test_empty_file(void __unused **state)
{
	/* An empty file is valid, it simply sets nothing. */
	assert_int_equal(load_config(""), 0);
}

static void test_nonexistent_file(void __unused **state)
{
	assert_int_equal(config_read_from_file("/nonexistent/path/to/config.yaml"), -EIO);
}

static void test_null_file(void __unused **state)
{
	assert_int_equal(config_read_from_file(NULL), -EINVAL);
}

/* ------------------------------------------------------------------------- */
/* Combined parsing and defaults                                             */
/* ------------------------------------------------------------------------- */

static void test_nested_yaml_multiple_classes(void __unused **state)
{
	static const char *yaml = "Application:\n"
				  "  ApplicationClockId: CLOCK_TAI\n"
				  "  ApplicationBaseCycleTimeNS: 1ms\n"
				  "TSNHigh:\n"
				  "  TsnHighEnabled: true\n"
				  "  TsnHighVid: 200\n"
				  "  TsnHighNumFramesPerCycle: 32\n"
				  "TSNLow:\n"
				  "  TsnLowEnabled: false\n"
				  "  TsnLowVid: 300\n";

	assert_int_equal(load_config(yaml), 0);
	assert_int_equal(app_config.application_clock_id, CLOCK_TAI);
	assert_int_equal(app_config.application_base_cycle_time_ns, 1000000ULL);
	assert_true(app_config.classes[TSN_HIGH_FRAME_TYPE].enabled);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].vid, 200);
	assert_int_equal(app_config.classes[TSN_HIGH_FRAME_TYPE].num_frames_per_cycle, 32);
	assert_false(app_config.classes[TSN_LOW_FRAME_TYPE].enabled);
	assert_int_equal(app_config.classes[TSN_LOW_FRAME_TYPE].vid, 300);
}

static void test_string_default_is_replaced(void __unused **state)
{
	/*
	 * config_set_defaults() allocates default strings. Parsing a file that
	 * overrides them must free the default and store the new value (checked
	 * indirectly by running under ASAN).
	 */
	assert_int_equal(config_set_defaults(false), 0);
	assert_non_null(app_config.log_level);

	assert_int_equal(load_config("LogLevel: Debug\n"), 0);
	assert_string_equal(app_config.log_level, "Debug");
}

static void test_defaults_pass_sanity_check(void __unused **state)
{
	assert_int_equal(config_set_defaults(false), 0);
	assert_true(config_sanity_check());
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		/* Data types */
		cmocka_unit_test_setup_teardown(test_type_bool, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_int, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_ulong, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_size, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_time, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_string, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_payload, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_interface, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_interface_truncation, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_mac, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_ether_type, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_security_mode, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_security_algorithm, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_cpu_list, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_clockid, setup, teardown),
		cmocka_unit_test_setup_teardown(test_type_protocol_type, setup, teardown),

		/* Invalid values */
		cmocka_unit_test_setup_teardown(test_invalid_bool, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_int, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_ulong, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_time, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_mac, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_ether_type, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_security_mode, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_security_algorithm, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_cpu_list, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_clockid, setup, teardown),
		cmocka_unit_test_setup_teardown(test_invalid_protocol_type, setup, teardown),

		/* Structural / file level errors */
		cmocka_unit_test_setup_teardown(test_unknown_global_option, setup, teardown),
		cmocka_unit_test_setup_teardown(test_unknown_class_option, setup, teardown),
		cmocka_unit_test_setup_teardown(test_option_on_wrong_traffic_class, setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_malformed_yaml, setup, teardown),
		cmocka_unit_test_setup_teardown(test_empty_file, setup, teardown),
		cmocka_unit_test_setup_teardown(test_nonexistent_file, setup, teardown),
		cmocka_unit_test_setup_teardown(test_null_file, setup, teardown),

		/* Combined */
		cmocka_unit_test_setup_teardown(test_nested_yaml_multiple_classes, setup, teardown),
		cmocka_unit_test_setup_teardown(test_string_default_is_replaced, setup, teardown),
		cmocka_unit_test_setup_teardown(test_defaults_pass_sanity_check, setup, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
