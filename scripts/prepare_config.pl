#!/usr/bin/env perl
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

use strict;
use warnings;
use Getopt::Long;

$| = 1;

my (@yaml_files, $help, $mac_src, $mac_dst, $ip_src, $ip_dst, $inf);

sub print_usage
{
	select(STDERR);

	print <<'EOF';
usage: prepare_config.pl [options] -- <yaml_files>

options:
    --help,    -h | Show this help
    --mac_src, -a | Source MAC Address
    --mac_dst, -b | Destination MAC Address
    --ip_src,  -c | Source IP Address
    --ip_dst,  -d | Destination IP Address
    --inf,     -i | Network interface name
EOF

	exit 0;
}

sub get_args
{
	GetOptions(
		"help"        => \$help,
		"a|mac_src=s" => \$mac_src,
		"b|mac_dst=s" => \$mac_dst,
		"c|ip_src=s"  => \$ip_src,
		"d|ip_dst=s"  => \$ip_dst,
		"i|inf=s"     => \$inf
	) || print_usage();

	@yaml_files = @ARGV;
	print_usage() unless @yaml_files;
}

sub process_yaml_file
{
	my ($file) = @_;
	my (@lines, $fh, $line, $mirror, $l2_dst, $l3_src, $l3_dst);

	$mirror = $file =~ /mirror/;

	$l2_dst = $mirror ? $mac_src : $mac_dst;
	$l3_dst = $mirror ? $ip_src  : $ip_dst;
	$l3_src = $mirror ? $ip_dst  : $ip_src;

	open $fh, '<', $file or die;

	while ($line = <$fh>) {
		$line =~
s/(TsnHigh|TsnLow|Rtc|Rta|Dcp|Lldp|UdpHigh|UpdLow|GenericL2)Interface: \w+/$1Interface: $inf/g
			if $inf;

		$line =~
s/(TsnHigh|TsnLow|Rtc|Rta|Dcp|Lldp|GenericL2)Destination: [0-9a-fA-F:]+/$1Destination: $l2_dst/g
			if $l2_dst;

		$line =~ s/(UdpHigh|UpdLow)Destination: \w+/$1Destination: $l3_dst/g
			if $l3_dst;

		$line =~ s/(UdpHigh|UpdLow)Source: \w+/$1Source: $l3_src/g
			if $l3_src;

		push @lines, $line;
	}

	close $fh;

	open $fh, '>', $file or die;
	print $fh $_ for @lines;
	close $fh;
}

get_args;

process_yaml_file $_ for @yaml_files;

exit 0
