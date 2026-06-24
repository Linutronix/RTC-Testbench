#!/usr/bin/env perl
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

use strict;
use warnings;

my ($hist, $min, $max);
my ($tsn_high, $tsn_low, $rtc, $rta, $dcp, $lldp, $udp_high, $udp_low, $g2);

sub write_data_file
{
	my ($file) = @_;
	my ($fh, $line, @lines, $rtt);

	$tsn_high = $tsn_low = $rtc = $rta = $dcp = $lldp = $udp_high = $udp_low = $g2 = 0;
	$max      = 0;
	$min      = 1e9;
	open($fh, "<", $file) or die("Failed to open file '$file': $!");
	while ($line = <$fh>) {
		my ($c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9);

		push(@lines, $line) if $line =~ /^\d+:/;

		if (($rtt) = $line =~ /^(\d+):/) {
			$max = $rtt if $rtt > $max;
			$min = $rtt if $rtt < $min;
		}

		if (($c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9) =
			$line =~
/^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/
			)
		{
			$tsn_high = 1 if $c1 != 0;
			$tsn_low  = 1 if $c2 != 0;
			$rtc      = 1 if $c3 != 0;
			$rta      = 1 if $c4 != 0;
			$dcp      = 1 if $c5 != 0;
			$lldp     = 1 if $c6 != 0;
			$udp_high = 1 if $c7 != 0;
			$udp_low  = 1 if $c8 != 0;
			$g2       = 1 if $c9 != 0;
		}
	}
	close($fh);

	open($fh, ">", "data.txt") or die;
	print $fh $_ for @lines;
	close($fh);
}

sub plot
{
	my ($file) = @_;
	my ($fh);

	$file =~ s/\.txt$//;
	$file .= ".png";

	$min =~ s/^0+//;
	$max =~ s/^0+//;

	$min -= 100;
	$max += 100;

	open($fh, ">", "plot.txt");
	print $fh "set terminal png size 1920,1080 enhanced font 'sans-serif,20'\n";
	print $fh "set output '$file';\n";
	print $fh "set title 'Testbench latency plot';\n";
	print $fh "set xlabel 'Latency [us]';\n";
	print $fh "set ylabel 'Number of latency samples';\n";
	print $fh "set ytics right;\n";
	print $fh "set logscale y;\n";
	print $fh "set xrange [$min:$max];\n";
	print $fh "set yrange [0.8:*];\n";
	print $fh "set grid back;\n";
	print $fh "plot ";
	print $fh "'data.txt' using 1:2 with fsteps lw 3 title 'TsnHigh', "    if $tsn_high;
	print $fh "'data.txt' using 1:3 with fsteps lw 3 title 'TsnLow', "     if $tsn_low;
	print $fh "'data.txt' using 1:4 with fsteps lw 3 title 'Rtc', "        if $rtc;
	print $fh "'data.txt' using 1:5 with fsteps lw 3 title 'Rta', "        if $rta;
	print $fh "'data.txt' using 1:6 with fsteps lw 3 title 'Dcp', "        if $dcp;
	print $fh "'data.txt' using 1:7 with fsteps lw 3 title 'Lldp', "       if $lldp;
	print $fh "'data.txt' using 1:8 with fsteps lw 3 title 'UdpHigh', "    if $udp_high;
	print $fh "'data.txt' using 1:9 with fsteps lw 3 title 'UdpLow', "     if $udp_low;
	print $fh "'data.txt' using 1:10 with fsteps lw 3 title 'GenericL2', " if $g2;
	print $fh ";\n";
	close($fh);

	`gnuplot plot.txt`;
	die("Gnuplot failed!") if $?;
}

sub cleanup
{
	`rm -f data.txt`;
	`rm -f plot.txt`;
}

sub print_usage
{
	select(STDERR);
	print "usage: plot_histogram.pl <histogram_file>\n";
	exit 0;
}

$hist = $ARGV[0];
print_usage unless $hist;

write_data_file($hist);
plot($hist);
cleanup;

exit 0;
