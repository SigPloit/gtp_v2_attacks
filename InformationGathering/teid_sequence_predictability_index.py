#!/usr/bin/env python
# encoding: utf-8
#       teid_sequence_predictability_index.py
#       
#       Copyright 2018 Rosalia d'Alessandro 
#                     
#

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
import os
import sys
from optparse import OptionParser


__all__ = []
__version__ = 0.1

DEFAULT_NUM_MSG = 6

DEBUG = 0


##
## ATTACKING TOOL 
## 
## @brief      Main file to execute the script.
## 
## This file roughly estimates how difficult it would be to predict the next 
## teid from the known sequence of six probe responses. 
##
## Use the -h option to enter the help menu and determine what to do.
## 
## Basic usage examples:
##      * $ python teid_sequence_predictability_index.py -v -t <teids>

'''
TCP ISN greatest common divisor (GCD)

The SEQ test sends six TCP SYN packets to an open port of the target machine and 
collects SYN/ACK packets back. Each of these SYN/ACK packets contains a 32-bit 
initial sequence number (ISN). This test attempts to determine the smallest number 
by which the target host increments these values. For example, many hosts (especially old ones) 
always increment the ISN in multiples of 64,000.

The first step in calculating this is creating an array of differences between
 probe responses. The first element is the difference between the 1st and 2nd 
 probe response ISNs. The second element is the difference between the 2nd and 
 3rd responses. There are five elements if Nmap receives responses to all six probes. S
 ince the next couple of sections reference this array, we will call it diff1. 
 If an ISN is lower than the previous one, Nmap looks at both the number of values 
 it would have to subtract from the first value to obtain the second, 
 and the number of values it would have to count up (including wrapping 
 the 32-bit counter back to zero). The smaller of those two values is stored 
 in diff1. So the difference between 0x20000 followed by 0x15000 is 0xB000. 
 The difference between 0xFFFFFF00 and 0xC000 is 0xC0FF. This test value 
 then records the greatest common divisor of all those elements. 
 This GCD is also used for calculating the SP result.
TCP ISN counter rate (ISR)

This value reports the average rate of increase for the returned 
TCP initial sequence number. Recall that a difference is taken between 
each two consecutive probe responses and stored in the previously discussed 
diff1 array. Those differences are each divided by the amount of time elapsed 
(in seconds—will generally be about 0.1) between sending the two probes which 
generated them. The result is an array, which we'll call seq_rates containing 
the rates of ISN counter increases per second. The array has one element for 
each diff1 value. An average is taken of the array values. If that average is
 less than one (e.g. a constant ISN is used), ISR is zero. Otherwise ISR is 
 eight times the binary logarithm (log base-2) of that average value, rounded
  to the nearest integer.
TCP ISN sequence predictability index (SP)

While the ISR test measures the average rate of initial sequence number 
increments, this value measures the ISN variability. It roughly estimates
 how difficult it would be to predict the next ISN from the known sequence 
 of six probe responses. The calculation uses the difference array (seq_rates) 
 and GCD values discussed in the previous section.

This test is only performed if at least four responses were seen. If the 
previously computed GCD value is greater than nine, the elements of the 
previously computed seq_rates array are divided by that value. We don't do 
the division for smaller GCD values because those are usually caused by chance. 
A standard deviation of the array of the resultant values is then taken. If the 
result is one or less, SP is zero. Otherwise the binary logarithm of the result 
is computed, then it is multiplied by eight, rounded to the nearest integer, 
and stored as SP.

Please keep in mind that this test is only done for OS detection purposes and 
is not a full-blown audit of the target ISN generator. There are many algorithm 
weaknesses that lead to easy predictability even with a high SP value.
'''
##sudo apt-get upgrade python-setuptools
##sudo apt-get install python-pip python-wheel
##sudo pip install numpy 

from numpy import uint32, int32, log2

def Mod32Diff(a,b):
    tmp1 = abs(a - b)
    tmp2 = abs(b - a)
    tmp = min(tmp1, tmp2)
    return uint32(tmp)

def GCD(seq_diffs):
    if seq_diffs == []:
        raise Exception('no difference values')
    seq_len = len(seq_diffs)
    a = uint32(seq_diffs[0])  #a = *val;
    i = 0
    while i < (seq_len -1) :
        i += 1
        b = uint32(seq_diffs[i])
        if (a < b):
            a,b = b,a
        while b:
            a,b = b, uint32(a%b)
    return a

def CalculateSeqDiffs(teids):
    seq_diffs = []
    i = 0
    seq_len = len(teids)
    if seq_len == 0:
        raise Exception("list of teids empty")
    if seq_len < 6 :
        raise Exception("list of teids too short, minimum 6 elements are required.")
    while i < (seq_len-1):
        t0 = teids[i]
        i += 1
        t1 = teids[i]
        seq_diffs.append(Mod32Diff(t0, t1))
        print "%d, %0.2x, %0.2x, %d"%(i, t0, t1, Mod32Diff(t0, t1))
    return seq_diffs

def CalculateAVGSeqDiffs(seq_diffs):
    avg = 0
    for sd in seq_diffs:
        avg += sd
    return avg/len(seq_diffs)

def CalculateModifiedStdSeqDiffs(seq_diffs, avg, gcd):
    if seq_diffs == []:
        raise Exception('no difference values')
    div_gcd = 1
    if gcd > 9 :
        div_gcd = gcd
    stddev = 0
    for sd in seq_diffs :
        rtmp = float((sd - avg)/ div_gcd)
        stddev += float(rtmp**2)
    stddev /= len(seq_diffs)
    return float(stddev**(1/2.0))
              
def CalculateSeqIndex(stddev):
    seq_index = 0
    if stddev > 1 :
        stddev = log2(stddev);
        seq_index = int(stddev * 8 + 0.5)
    return seq_index

def SeqIndex2DifficultyStr(seq_index) :
    if seq_index < 3 :
        return "Trivial joke"
    if seq_index < 6 :
        return "Easy"
    if seq_index < 11 :
        return "Medium"
    if seq_index < 12 :
        return "Formidable"
    if seq_index < 16 :
        return  "Worthy challenge"
    return "Good luck!";


def main(argv=None):
    '''Command line options.'''

    program_name = os.path.basename(sys.argv[0])
    program_version = "v0.1"

    program_version_string = '%%prog %s' % (program_version)

    program_license = "Copyright 2018 Rosalia d'Alessandro\
                Licensed under the Apache License 2.0\
                nhttp://www.apache.org/licenses/LICENSE-2.0"

    if argv is None:
        argv = sys.argv[1:]
    lstn = None
    try:
        # setup option parser
        parser = OptionParser(version=program_version_string, description=program_license)
        parser.add_option("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %default]")

        parser.add_option("-t", "--teids", dest="teids_file", help="file containing list of at least six consecutives tests")
      
        
        # set defaults
        parser.set_defaults(teids_file="teids.cnf", 
                            verbose = False)

        # process options
        (opts, args) = parser.parse_args(argv)
        is_verbose = False
 
        # MAIN BODY #
        if opts.teids_file == "" :
            print "Error: missed file containing at least six consecutive teids"
            return            
        ##read file
        teids = []
        with open(opts.teids_file) as f:
            teids = f.readlines()
        teids = [int(t.strip(),16) for t in teids]
        
        if len(teids) < 6:
            print ("Error: File shall containat least six consecutive teids.",
                   "provided %d")%(len(teids))
            return           
        seq_diffs = CalculateSeqDiffs(teids)
        gcd = GCD(seq_diffs)
        seq_index = 0
        if gcd == 0:
            print "FIXED TEIDS"
        elif gcd > 0 :
            avg = CalculateAVGSeqDiffs(seq_diffs)
            stddev = CalculateModifiedStdSeqDiffs(seq_diffs, avg, gcd)
            seq_index = CalculateSeqIndex(stddev)
            print SeqIndex2DifficultyStr(seq_index)
        else :
            raise Exception("Negative GCD")
       
    except Exception, e:
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        print "Exception %s"%str(e)       
        return 2
if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-v")
    sys.exit(main())
