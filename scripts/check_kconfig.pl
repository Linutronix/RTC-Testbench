#!/usr/bin/env perl
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2026 Linutronix GmbH
# Kurt Kanzenbach <kurt@linutronix.de>
#
# Check Linux kernel configuration for RTC TB.
#

use strict;
use warnings;
use version;
use utf8;
use Data::Dumper;
use Getopt::Long;
use Term::ANSIColor qw(:constants);

# config
my (%config, @err, @warn, @musthave, @disabled, $file, $help);

# Must have options
@musthave = (
    # PREEMPT_RT
    "CONFIG_PREEMPT_RT",
    "CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE",
    "CONFIG_HIGH_RES_TIMERS",
    # Networking
    "CONFIG_PTP_1588_CLOCK",
    "CONFIG_BPF",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_DEBUG_INFO",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_XDP_SOCKETS",
    "CONFIG_NET_SCH_MQPRIO",
    "CONFIG_NET_SCH_TAPRIO",
    "CONFIG_NET_SCH_ETF",
    "CONFIG_NET_SCH_INGRESS",
    "CONFIG_NET_CLS",
    "CONFIG_NET_CLS_FLOWER",
    "CONFIG_VLAN_8021Q",
    "CONFIG_MACVLAN",
    "CONFIG_VETH",
    "CONFIG_POSIX_AUX_CLOCKS",
    "CONFIG_NET_RX_BUSY_POLL",
   );

# Should be disabled
@disabled = (
    # PREEMPT_RT
    "CONFIG_NO_HZ_IDLE",
    "CONFIG_PROVE_LOCKING",
    "CONFIG_DRM",		# For example, i915 may cause latency
   );

sub print_usage_and_die
{
    select STDERR;

    local $| = 1;

    print <<"EOF";
usage: $0 [options] <config_file>

options:
    --help, -h: Show this help text
EOF

    exit -1;
}

sub get_args
{
    GetOptions("help" => \$help,
              ) || print_usage_and_die();

    print_usage_and_die() if $help;
    $file = shift @ARGV;
    print_usage_and_die() unless $file;

    return;
}

sub kurt_err
{
    my ($msg) = @_;
    my (undef, undef, undef, $sub)  = caller(1);
    my (undef, $file, $line, undef) = caller(0);

    print_red("[ERROR in $sub $file:$line]: $msg\n");

    exit -1;
}

sub print_red
{
    my ($msg) = @_;

    print STDERR BOLD RED "$msg", RESET;

    return;
}

sub print_yellow
{
    my ($msg) = @_;

    print STDERR BOLD YELLOW "$msg", RESET;

    return;
}

sub print_green
{
    my ($msg) = @_;

    print BOLD GREEN "$msg", RESET;

    return;
}

sub print_bold
{
    my ($msg) = @_;

    print BOLD "$msg", RESET;

    return;
}

sub read_config
{
    my ($fh, $line);

    open($fh, "<", $file) || kurt_err("Failed to open file '$file': $!");

    while ($line = <$fh>) {
        my ($conf, $value);

        next if $line =~ /^#/;
        next if $line =~ /^\s+/;

        unless (($conf, $value) = $line =~ /(CONFIG_.*?)=(.*)/) {
            kurt_err("Failed to parse line '$line' in config file '$file'");
        }

        $config{$conf} = "enabled";
    }

    close($fh);

    return;
}

sub add_err
{
    my ($msg) = @_;

    push(@err, $msg);

    return;
}

sub add_warn
{
    my ($msg) = @_;

    push(@warn, $msg);

    return;
}

sub check_config
{
    my (@debug);

    foreach my $opt (@musthave) {
	add_err("Option '$opt' is not set while it should be!")
	    unless exists ($config{$opt});
    }

    foreach my $opt (@disabled) {
	add_err("Option '$opt' is set while it should not be!")
	    if exists ($config{$opt});
    }

    @debug = grep { $_ =~ /DEBUG/ } keys %config;
    @debug = grep { $_ !~ /FS/ } @debug;
    @debug = grep { $_ !~ /ARCH_HAS/ } @debug;
    @debug = grep { $_ !~ /SUPPORT/ } @debug;
    @debug = grep { $_ !~ /HAVE/ } @debug;
    @debug = grep { $_ ne "CONFIG_DEBUG_INFO" } @debug;
    @debug = grep { $_ ne "CONFIG_DEBUG_INFO_BTF" } @debug;
    @debug = grep { $_ ne "CONFIG_DEBUG_INFO_NONE" } @debug;

    foreach (@debug) {
        add_warn("DEBUG option '$_' enabled");
    }

    return;
}

sub main
{
    get_args();
    read_config();
    check_config();

    print_green("Checking config file '$file'...\n");

    print_red("The following errors have been found:\n") if @err > 0;
    for my $msg (sort @err) {
        print "\t$msg\n";
    }

    print_yellow("The following warnings have been found:\n") if @warn > 0;
    for my $msg (sort @warn) {
        print "\t$msg\n";
    }

    return;
}

main();

exit 0;
