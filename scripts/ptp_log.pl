#!/usr/bin/env perl
#
# Copyright (C) 2026 Linutronix GmbH
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Parses ptp4l/phc2sys logging messages and converts them into JSON objects to be published via
# MQTT. The purpose is to get the time sync accuracy into Grafana as well.
#
# To be used like this: ptp4l ... | ptp_log.pl -s ptp4l -m <measurement_name>
#                       phc2sys ... | ptp_log.pl -s phc2sys -m <measurement_name>
#

use strict;
use warnings;
use Getopt::Long;
use Time::HiRes qw(gettimeofday);
use Net::MQTT::Simple;
use JSON::PP;

# Config
my ($help, $source, $broker, $port, $topic, $measurement);

# Default settings
$topic  = "ptp";
$broker = "localhost";
$port   = 1883;

sub print_usage_and_die
{
    select(STDERR);

    print <<'EOF';
usage: ptp_log.pl [options]

options:
    --help, -h        | Show this help text
    --source, -s      | Either 'ptp4l' or 'phc2sys'
    --broker, -b      | IP of MQTT broker
    --port, -p        | Port of MQTT broker
    --measurement, -m | Measurement name

Run like this: ptp4l .... | ./ptp_log.pl -s <ptp4l|phc2sys> -m <measurement_name>
EOF

    exit 1;
}

sub get_args
{
    GetOptions("help"          => \$help,
	       "source=s"      => \$source,
	       "broker=s"      => \$broker,
	       "port=i"        => \$port,
	       "measurement=s" => \$measurement)
	|| print_usage_and_die();
    print_usage_and_die() if $help;
    print_usage_and_die() unless $source;
    print_usage_and_die() unless $measurement;
    print_usage_and_die() if $source ne "ptp4l" && $source ne "phc2sys";
}

sub main
{
    my ($mqtt, $line);

    get_args();

    $mqtt = Net::MQTT::Simple->new("$broker:$port") or die "Failed to connect to MQTT broker!";

    while ($line = <STDIN>) {
        my ($payload, $rms_ns, $max_ns, $offset_ns, $freq_ppb, $delay_ns, $sec, $usec);

        $max_ns = $rms_ns = $offset_ns = $freq_ppb = $delay_ns = 0;

        if ($source eq "ptp4l") {
            next unless (($rms_ns, $max_ns, $freq_ppb, $delay_ns) = $line =~ /rms\s+(-?\d+)\s+max\s+(-?\d+).*?freq\s+(-?\d+).*?delay\s+(-?\d+)/);
        } else {
            next unless (($offset_ns, $freq_ppb, $delay_ns) = $line =~ /offset\s+(-?\d+)\s+\w+\s+freq\s+([+-]?\d+)\s+delay\s+(\d+)/);
        }

        ($sec, $usec) = gettimeofday();
        $payload = encode_json({
            ptp => {
                Timestamp       => $sec * 1_000_000_000 + $usec * 1_000,
                MeasurementName => $measurement,
                stats           => {
                    max_ns      => int($max_ns),
                    rms_ns      => int($rms_ns),
                    offset_ns   => int($offset_ns),
                    freq_ppb    => int($freq_ppb),
                    delay_ns    => int($delay_ns),
                },
            },
        });

        $mqtt->publish($topic => $payload);
    }
}

main();

exit 0;
