#!/usr/bin/env python3
#
# Copyright (C) 2024 Intel Corporation
# Author Walfred Tedeschi <walfred.tedeschi@intel.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Parse PcapNG files produced by Profishark and plot interpacket gap, etc.
#

import argparse
import binascii
import pathlib

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from beautifultable import BeautifulTable
from scapy.layers.l2 import Dot1Q
from scapy.utils import PcapReader

preambleLength = 7 + 1
crcLength = 4
headerLength = 18  # With Vlan
fullOverhead = preambleLength + crcLength + headerLength

tclass_cycle_time = 0.001


class Stats:
    def __init__(self):
        self.IPG = {
            "count": 0,
            "mean": 0,
            "std" "min": 0,
            "Q25": 0,
            "Q50": 0,
            "Q75": 0,
            "max": 0,
        }
        self.BatchStart = {
            "count": 0,
            "mean": 0,
            "std" "min": 0,
            "Q25": 0,
            "Q50": 0,
            "Q75": 0,
            "max": 0,
        }
        self.BatchEnd = {
            "count": 0,
            "mean": 0,
            "std" "min": 0,
            "Q25": 0,
            "Q50": 0,
            "Q75": 0,
            "max": 0,
        }
        self.BatchCount = {
            "count": 0,
            "mean": 0,
            "std" "min": 0,
            "Q25": 0,
            "Q50": 0,
            "Q75": 0,
            "max": 0,
        }
        self.cycles = 0
        self.packetLenght = 0


def create_main_table():
    global tclass_start_cycle
    ipgTable = BeautifulTable(precision=4)
    ipgTable.rows.append(["count", "min", "mean", "std", "Q25", "Q50", "Q75", "max"])
    ipgTable.columns.width = [14, 14, 14, 14, 14, 14, 14, 14]
    ipgTable.border.left = ""
    ipgTable.border.right = ""
    ipgTable.border.top = ""
    ipgTable.border.bottom = ""

    # Batch Count
    bcTable = BeautifulTable(precision=4)
    bcTable.rows.append(["min", "mean", "max"])
    bcTable.columns.width = [5, 6, 5]
    bcTable.border.left = ""
    bcTable.border.right = ""
    bcTable.border.top = ""
    bcTable.border.bottom = ""
    # Batch Start
    bsTable = BeautifulTable(precision=4)
    bsTable.rows.append(["min", "mean", "max"])
    bsTable.columns.width = [14, 14, 14]
    bsTable.border.left = ""
    bsTable.border.right = ""
    bsTable.border.top = ""
    bsTable.border.bottom = ""
    # Batch End
    beTable = BeautifulTable(precision=4)
    beTable.rows.append(["min", "mean", "max"])
    beTable.columns.width = [14, 14, 14]
    beTable.border.left = ""
    beTable.border.right = ""
    beTable.border.top = ""
    beTable.border.bottom = ""

    # Main table
    mainTable = BeautifulTable(maxwidth=500)
    mainTable.columns.header = [
        "Traffic Class",
        "Cycles",
        "Pkt Len",
        "Batch Count",
        "IPG",
        "Batch Start",
        "Batch End",
    ]

    # mainTable.columns.header = [ "Traffic Class",
    #                             "Cycles",
    #                             "Pkt Len",
    #                            "Batch Count",
    #                             "IPG" ]
    mainTable.rows.append(
        ["Cycle Time (s)", tclass_cycle_time, "", bcTable, ipgTable, bsTable, beTable]
    )

    # mainTable.rows.append(["Cycle Time (s)", tclass_cycle_time, "", bcTable, ipgTable])

    return mainTable


def populate_stats(stats, className, table):
    global tclass_start_cycle
    resultIPGTable = BeautifulTable(precision=4)
    try:
        resultIPGTable.rows.append(
            [
                stats.IPG["count"],
                stats.IPG["min"],
                stats.IPG["mean"],
                stats.IPG["std"],
                stats.IPG["Q25"],
                stats.IPG["Q50"],
                stats.IPG["Q75"],
                stats.IPG["max"],
            ]
        )
    except:
        print("not enough data to calculate IPG")

    resultIPGTable.columns.width = [14, 14, 14, 14, 14, 14, 14, 14]
    resultIPGTable.border.left = ""
    resultIPGTable.border.right = ""
    resultIPGTable.border.top = ""
    resultIPGTable.border.bottom = ""

    resultBCTable = BeautifulTable(precision=0)

    try:
        resultBCTable.rows.append(
            [stats.BatchCount["min"], stats.BatchCount["mean"], stats.BatchCount["max"]]
        )
    except KeyError:
        print("Missing Batch count values")

    resultBCTable.columns.width = [5, 6, 5]
    resultBCTable.border.left = ""
    resultBCTable.border.right = ""
    resultBCTable.border.top = ""
    resultBCTable.border.bottom = ""

    resultBSTable = BeautifulTable(precision=6)
    try:
        resultBSTable.rows.append(
            [stats.BatchStart["min"], stats.BatchStart["mean"], stats.BatchStart["max"]]
        )
    except KeyError:
        print("Missing Batch start values")

    resultBSTable.columns.width = [14, 14, 14]
    resultBSTable.border.left = ""
    resultBSTable.border.right = ""
    resultBSTable.border.top = ""
    resultBSTable.border.bottom = ""

    resultBETable = BeautifulTable(precision=6)
    try:
        resultBETable.rows.append(
            [stats.BatchEnd["min"], stats.BatchEnd["mean"], stats.BatchEnd["max"]]
        )
    except KeyError:
        print("Missing Batch start end")

    resultBETable.columns.width = [14, 14, 14]
    resultBETable.border.left = ""
    resultBETable.border.right = ""
    resultBETable.border.top = ""
    resultBETable.border.bottom = ""
    table.rows.append(
        [
            className,
            stats.cycles,
            stats.packetLenght,
            resultBCTable,
            resultIPGTable,
            resultBSTable,
            resultBETable,
        ]
    )
    # table.rows.append([className,
    #                   stats.cycles,
    #                   stats.packetLenght,
    #                   resultBCTable,
    #                   resultIPGTable])


def cycleOffset(cycleCounter, pkt_time, startTime):
    global tclass_cycle_time
    currCycleTime = (cycleCounter - 1) * tclass_cycle_time
    deltaTime = pkt_time - startTime
    # if cycleCounter < 4:
    res = deltaTime - currCycleTime
    return res


class TrafficClass:
    global tclass_start_cycle

    def __init__(self, pcp, tcName):
        self.pcp = pcp
        self.tcName = tcName
        self.DeltaTime = []
        self.DTimeTime = []
        self.IPG = []
        self.IPGTime = []
        self.framesWithinCycle = []
        self.framesWithinCycleTime = []
        self.batch_End = []
        self.batch_Start = []
        self.burstTime = []
        self.aveIPGInBurst = []
        self.countIPG = 0
        self.lengths = []
        self.deltaPktTime = 0
        self.prevPktTime = 0
        self.curpktTime = 0
        self.bytesStransmitedPerBurst = 0
        self.framesInBurst = 0
        self.prevPktLength = 0
        self.firstCycle = -1
        self.cycleCounter = -1
        self.currentCycle = -1
        self.curCycleTime = 0
        self.transmitTime = 0
        self.burstTimeStart = 0
        self.burstTimeEnd = 0
        self.missingWithinACycle = 0
        self.cur_batch_end = 0
        self.cur_batch_start = 0
        self.dataframeIPG = None
        self.dataframeAveIPG = None
        self.sequenceErrors = 0
        self.prevSequenceCounter = 0
        self.stats = Stats()

    def processPkt(self, pkt, cycleCounter, sequenceCounter):
        global fullOverhead

        if self.firstCycle == -1:
            self.firstCycle = cycleCounter
            self.cycleCounter = cycleCounter
            self.currentCycle = cycleCounter

        self.prevPktTime = self.curpktTime

        if self.firstCycle == cycleCounter:
            return

        self.curpktTime = pkt.time
        self.deltaPktTime = self.curpktTime - self.prevPktTime

        pktLen = headerLength + len(pkt.load)
        if pktLen not in self.lengths:
            self.lengths.append(pktLen)

        # Middle of the burst
        if self.currentCycle == cycleCounter:
            self.framesInBurst = self.framesInBurst + 1
            if self.currentCycle > self.firstCycle + 1:
                self.IPG.append(float((self.deltaPktTime - self.transmitTime) * 1e6))
                self.IPGTime.append(float(pkt.time))
                self.countIPG = self.countIPG + 1
                self.DeltaTime.append(self.deltaPktTime)
                self.DTimeTime.append(pkt.time)
                if self.prevSequenceCounter > sequenceCounter:
                    self.sequenceErrors = self.sequenceErrors + 1

        if self.currentCycle != cycleCounter:
            if self.cycleCounter > self.firstCycle + 1:
                self.batch_End.append(self.prevPktTime - self.burstTimeEnd)
            self.burstTimeEnd = self.prevPktTime
            if self.cycleCounter > self.firstCycle + 1:
                self.framesWithinCycle.append(self.framesInBurst)
                self.framesWithinCycleTime.append(pkt.time)
                # burstTime = self.burstTimeEnd - self.burstTimeStart
                # print(self.pcp, self.currentCycle, sequenceCounter, self.framesInBurst, burstTime)
            if self.cycleCounter > self.firstCycle + 1:
                self.batch_Start.append(self.curpktTime - self.burstTimeStart)
            self.burstTimeStart = self.curpktTime
            self.cycleCounter = self.cycleCounter + 1
            self.framesInBurst = 1
            self.currentCycle = cycleCounter

        self.prevPktLength = len(pkt.load) + fullOverhead
        self.bytesStransmitedPerBurst = (
            self.bytesStransmitedPerBurst + self.prevPktLength
        )
        self.transmitTime = (self.prevPktLength * 8) / 1e9
        self.prevSequenceCounter = sequenceCounter

    def plotMe(self, fileName):
        if len(self.DeltaTime) == 0:
            return
        print(self.lengths)
        nofFrames = max(self.framesWithinCycle)
        fig, axs = plt.subplots(2, 2, sharex=True)
        fig.suptitle(
            self.tcName
            + " "
            + str(self.prevPktLength)
            + "bytes x"
            + str(nofFrames)
            + " Time trace"
        )
        axs[0, 0].plot(self.DTimeTime, self.DeltaTime, "ro")
        axs[0, 0].set_title("Delta Time between packets")
        axs[0, 0].set(xlabel="Time(s)", ylabel="Delta in us")
        axs[0, 1].plot(self.IPGTime, self.IPG, "ro")
        axs[0, 1].set_title("IPG (us)")
        axs[0, 1].set(xlabel="Time (s)", ylabel="IPG in us")
        axs[1, 1].plot(self.framesWithinCycleTime, self.framesWithinCycle, "ro")
        Title = "Frames per burst " + str(nofFrames)
        axs[1, 1].set_title(Title)
        axs[1, 1].set(xlabel="Time (s)", ylabel="Count of frames per burst")
        plt.show()

    def plotMeSplit(self, fileName):
        if len(self.DeltaTime) == 0:
            return
        print(self.lengths)
        nofFrames = max(self.framesWithinCycle)

        plt.plot(self.DTimeTime, self.DeltaTime, "ro")
        plt.title(self.tcName + " " + "Delta Time between packets")
        plt.xlabel(xlabel="Time(s)")
        plt.ylabel(ylabel="Delta in us")
        plt.show()
        plt.plot(self.IPGTime, self.IPG, "ro")
        plt.title(self.tcName + " " + "IPG (us)")
        plt.xlabel("Time (s)")
        plt.ylabel("IPG in us")
        plt.show()
        plt.plot(self.framesWithinCycleTime, self.framesWithinCycle, "ro")
        plt.title(self.tcName + " " + "Frames per burst " + str(nofFrames))
        plt.xlabel("Time (s)")
        plt.ylabel("Count of frames per burst")
        plt.show()

    def getDataFrameIPG(self):
        nofFrames = max(self.framesWithinCycle)
        title = (
            self.tcName + ": " + str(self.prevPktLength) + "bytes x" + str(nofFrames)
        )
        print(title)
        self.dataframeIPG = pd.DataFrame(self.IPG[:])
        # self.dataframeIPG.set_axis({title}, axis=1, inplace=True)
        self.dataframeIPG.set_axis({title}, axis=1)
        return self.dataframeIPG

    def getLengths(self):
        print(self.lengths)
        return " - ".join(str(le) for le in self.lengths)

    def getDataFrameIPGwithinBurst(self):
        nofFrames = max(self.framesWithinCycle)
        title = self.tcName + ": " + str(nofFrames) + " within the burst"
        print(title)
        self.dataframeAveIPG = pd.DataFrame(self.aveIPGInBurst[:])
        # self.dataframeAveIPG.set_axis({title}, axis=1, inplace=True)
        self.dataframeAveIPG.set_axis({title}, axis=1)
        return self.dataframeAveIPG

    def describe(self):
        self.dataframeIPG = self.getDataFrameIPG()
        print(self.dataframeIPG.describe())
        print(self.getDataFrameIPGwithinBurst().describe())

    def getStats(self):
        df = pd.DataFrame(self.batch_End[:])
        try:
            self.stats.BatchEnd["count"] = float(df.count())
            self.stats.BatchEnd["min"] = float(df.min())
            self.stats.BatchEnd["max"] = float(df.max())
            self.stats.BatchEnd["mean"] = float(df.mean())
            self.stats.BatchEnd["std"] = float(df.std())
            self.stats.BatchEnd["Q25"] = df.quantile(0.25)
            self.stats.BatchEnd["Q50"] = df.quantile(0.50)
            self.stats.BatchEnd["Q75"] = df.quantile(0.75)
        except TypeError:
            print("Not Possible to process Batch end")

        df = pd.DataFrame(self.batch_Start[:])
        try:
            self.stats.BatchStart["min"] = float(df.min())
            self.stats.BatchStart["max"] = float(df.max())
            self.stats.BatchStart["mean"] = float(df.mean())
        except TypeError:
            print("Not Possible to process Batch start")

        df = pd.DataFrame(self.IPG[:])
        try:
            self.stats.IPG["count"] = float(df.count().iloc[0])
            self.stats.IPG["min"] = float(df.min().iloc[0])
            self.stats.IPG["max"] = float(df.max().iloc[0])
            self.stats.IPG["mean"] = float(df.mean().iloc[0])
            self.stats.IPG["std"] = float(df.std().iloc[0])
            self.stats.IPG["Q25"] = float(df.quantile(0.25).iloc[0])
            self.stats.IPG["Q50"] = float(df.quantile(0.50).iloc[0])
            self.stats.IPG["Q75"] = float(df.quantile(0.75).iloc[0])
        except TypeError:
            print("Not Possible to process IPG")

        df = pd.DataFrame(self.framesWithinCycle[1:])
        try:
            self.stats.BatchCount["min"] = int(df.min().iloc[0])
            self.stats.BatchCount["max"] = int(df.max().iloc[0])
            self.stats.BatchCount["mean"] = int(df.mean().iloc[0])
            self.stats.cycles = self.cycleCounter
            self.stats.packetLenght = self.getLengths()
        except TypeError:
            print("Not Possible to process Batch Count")
        print(
            "for the pcp ", self.pcp, ",", self.sequenceErrors, " sequence errors found"
        )
        return self.stats

    def hasDataAvailable(self):
        return 1 if len(self.DeltaTime) != 0 else 0


pktCounter = []
pktTime = []
pcp = []


def print_payload(pkt):
    message = pkt.payload.payload.decode()
    message_len = len(message)
    left = 0
    right = 8
    loop = int(message_len / 16) + 1
    for i in range(loop):
        print(
            " " * 8,
            i,
            " :",
            binascii.hexlify(message[left:right]),
            binascii.hexlify(message[left + 8 : right + 8]),
        )
        left += 16
        right += 16


def process_pcap(file_name):

    TrafficClasses = dict()

    print("Opening {}...".format(file_name))

    firstObservedCycle = -1
    interesting_packet_count = 0
    count = 0
    local_file = open(file_name, "rb")
    r = PcapReader(local_file)
    for pkt in r:
        count += 1

        if pkt.type == 0x8100:
            vlan_pkt = pkt[Dot1Q]

            pktCounter.append(count)
            pktTime.append(float(pkt.time))
            prio = vlan_pkt.fields["prio"]
            pcp.append(vlan_pkt.fields["prio"])

            if prio not in TrafficClasses:
                TrafficClasses[prio] = TrafficClass(prio, "PCP " + str(prio))

            sequenceCounter = int.from_bytes(pkt.load[2:6], "big")
            cycleCounter = int.from_bytes(pkt.load[6:10], "big")
            # frameId = int.from_bytes(pkt.load[0:2], "big")
            # payloadStr = pkt.load[10:34].decode("utf-8")
            # print (prio, cycleCounter, sequenceCounter, frameId, payloadStr)

            if firstObservedCycle == -1:
                firstObservedCycle = cycleCounter

            if cycleCounter == firstObservedCycle:
                continue

            TrafficClasses[prio].processPkt(pkt, cycleCounter, sequenceCounter)

        continue

        interesting_packet_count += 1
    # return
    plt.plot(pktCounter, pcp, "ro")
    plt.title("Packet order")
    plt.ylabel("PCP value")
    plt.xlabel("Count units")
    plt.show()

    plt.plot(pktTime, pcp, "ro")
    plt.title("Packet order in time")
    plt.ylabel("PCP value")
    plt.xlabel("Time")
    plt.show()

    for key in TrafficClasses:
        TrafficClasses[key].plotMe(file_name)
        # TrafficClasses[key].plotMeSplit(file_name)
        # TrafficClasses[key].describe()

    mainTable = create_main_table()
    for key in TrafficClasses:
        if TrafficClasses[key].hasDataAvailable():
            stats = TrafficClasses[key].getStats()
            populate_stats(stats, key, mainTable)
    print(mainTable)

    names = [key for key in TrafficClasses if TrafficClasses[key].hasDataAvailable()]
    for name in names:
        allDF = TrafficClasses[name].getDataFrameIPG()
        allDF = allDF.fillna(allDF.mean())
        ax = sns.boxplot(data=allDF)
        title = "IPG Boxplot: " + " ".join(str(names))
        ax.set_title(title)
        ax.set_ylabel("IPG (us)")
        plt.show()

    print(
        "{} contains {} packets ({} interesting)".format(
            file_name, count, interesting_packet_count
        )
    )


def main():
    global tclass_cycle_time
    parser = argparse.ArgumentParser(
        description="Process long term data recorded with TSN dashboard  \
    generating graphics and statistics summary for the key performance indicators."
    )

    parser.add_argument(
        "--file",
        metavar="file",
        type=pathlib.Path,
        help="Name of the file generated by the profishark (pcapng)",
        required=True,
    )

    parser.add_argument(
        "-c",
        "--cycle-time",
        help="Cycle time (second). Default 0.0005s (500us)",
        type=float,
        required=False,
        default=0.0005,
    )

    args = parser.parse_args()

    tclass_cycle_time = args.cycle_time

    process_pcap(args.file)


if __name__ == "__main__":
    main()
