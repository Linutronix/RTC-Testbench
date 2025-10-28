#!/usr/bin/env perl
#
# Copyright (C) 2025 Linutronix GmbH
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Listens to JSON/UDP messages on given port and prints desired statistics.
#
# Example: ./stat.pl -p 8888 -m testbench1 -t TsnHigh
# Example: ./stat.pl -p 8888 -m testbench1 -t TsnHigh -s FramesSent -s FramesReceived -s Tx* -s Rx*
#
# YAML Snippet:
#
# Json:
#   LogJson: true
#   LogJsonThreadPriority: 1
#   LogJsonThreadCpu: 0
#   LogJsonHost: 127.0.0.1
#   LogJsonPort: 8888
#   LogJsonMeasurementName: testbench1
#

use strict;
use warnings;
use Getopt::Long;
use JSON;
use IO::Socket::IP;

$| = 1;

my ($server, $port, $help, $measurement, $tc, @stats);

sub print_usage
{
    select(STDERR);

    print <<'EOF';
usage: stat.pl [options]

options:
    --help, -h        | Show this help
    --port, -p        | JSON/UDP port to listen on
    --measurement, -m | Measurement name
    --tc, -t          | Traffic class
    --stats, -s       | Statistics to print, can contain multiple values
EOF

	exit 0;
}

sub get_args
{
    GetOptions("help"          => \$help,
	       "port=s"        => \$port,
	       "measurement=s" => \$measurement,
	       "tc=s"          => \$tc,
	       "stats=s"       => \@stats)
	|| print_usage;
    print_usage if $help;
    print_usage unless $port;
}

sub main
{
    my ($peer, $data, $json);

    # Open UDP server socket
    $server = IO::Socket::IP->new(LocalPort => $port,
				  Proto     => "udp")
	or die "Could not open UDP socket on $port: $@\n";

    # Receive datagrams
    while ($peer = $server->recv($data, 4096)) {
	$json = decode_json $data;

	if ($measurement) {
	    next unless $json->{reference}{MeasurementName} eq $measurement;
	}

	if ($tc) {
	    next unless $json->{reference}{stats}{TCName} eq $tc;
	}

	print "Measurement: $measurement -- TC: $json->{reference}{stats}{TCName}\n";
	foreach my $stat (sort keys %{ $json->{reference}{stats} }) {
	    if (scalar @stats) {
		next unless grep $stat =~ /$_/, @stats;
	    }

	    print "  $stat: $json->{reference}{stats}{$stat}\n";
	}
    }
}

get_args;
main;

exit 0
