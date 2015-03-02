#!/usr/bin/env python

import frame_pb2 as pb
import struct
import getopt
import sys
import IPython
import pickle
from collections import defaultdict
import google   

FMT_TXT=0x1
FMT_PKL_HIGHLIGHT=0x2
FMT_UNIQ_INSNS=0x3

def getFrameLength(f):
        return struct.unpack("Q", f.read(8))[0]

def getFrame(f):
        return pb.frame.FromString(f.read(getFrameLength(f)))

#bitsize to format
btf = {8 : 'b', 32 : 'I'}

def printOperandList(l):
        #IPython.embed()
        res = ""
        regs = filter(lambda x : x.operand_info_specific.ListFields()[0][0].name == "reg_operand", l)
        mems = filter(lambda x : x.operand_info_specific.ListFields()[0][0].name == "mem_operand", l)
        for o in regs:
                v = struct.unpack("I", o.value)[0]
                res += "\treg: %s, value: 0x%08lx\n" % (o.operand_info_specific.reg_operand.name, v)
        res.strip()
        for o in mems:
                v = struct.unpack(btf[o.bit_length], o.value)[0]
                res += "\tmem: 0x%08lx, value: 0x%08lx\n" % (o.operand_info_specific.mem_operand.address, v)
        res.strip()
        return res

def skipFrames(infile, cnt):
        fr = None
        for x in range(0, cnt):
            fr = getFrame(infile)
        return fr

def gotoFrame(infile, cnt):
        infile.seek(0x30)
        return skipFrames(infile, cnt)

def gotoAddress(infile, addr, debug=False):
        infile.seek(0x30)
        fr = getFrame(infile)
        cnt = 1
        while fr.std_frame.address != addr:
                fr = getFrame(infile)
                cnt += 1
        if debug and fr.std_frame.address == addr:
                print "Frame # %i is at addr: 0x%08lx" % (cnt, addr)
        return fr

def printFrame(f):
        print "PRE: %s" % printOperandList(f.std_frame.operand_pre_list.elem)
        print "POST: %s" % printOperandList(f.std_frame.operand_post_list.elem)

def process(infileName, outfileName=None, maxCnt=0, outFormat=FMT_TXT):
        out = sys.stdout
        if outfileName:
                out = open(outfileName, 'w')
        infile = open(infileName)

        (infile, metaMaxCnt) = getMetaData(infile)

        if maxCnt == 0:
                maxCnt = metaMaxCnt

        cnt = 0

        print "maxCnt: %i" % maxCnt

        insns = defaultdict(lambda : 0)
        while (cnt <= maxCnt):
                cnt += 1
                try:
                    fr = getFrame(infile)
                    insns[fr.std_frame.address]+=1 
                except google.protobuf.message.DecodeError, e:
                    print "maxCnt: %i, cnt: %i\n" % (maxCnt, cnt)
                    print e
                    break
                if outFormat == FMT_TXT:
                    out.write("0x%x, %r\n" % (fr.std_frame.address, fr.std_frame.rawbytes))

        if outFormat == FMT_PKL_HIGHLIGHT:
            highlight_data = {1:set(insns.keys())}
            pickle.dump(highlight_data, out)
        elif outFormat == FMT_UNIQ_INSNS:
            out.write("\n".join(["0x%x" % i for i in set(insns.keys())]))

def getMetaData(f):
        f.seek(0x20)
        numFrames = struct.unpack("Q", f.read(8))[0] - 1
        f.seek(0x30) #move to first frame
        return(f, numFrames)
        
def main():
        debug = 0
        maxCnt = 0
        infile = None
        outfile = None
        outFormat = FMT_TXT
        opts,argv = getopt.getopt(sys.argv[1:], "f:c:o:F:d") 
        for k,v in opts:
                if k == '-d':
                        debug += 1
                if k == '-f':
                        infile = v
                if k == '-o':
                        outfile = v
                if k == '-c':
                        maxCnt = int(v)
                if k == '-F':
                        if v == 'pkl':
                            outFormat = FMT_PKL_HIGHLIGHT
                        elif v == 'uniq':
                            outFormat = FMT_UNIQ_INSNS

        if infile:
                process(infile, outfile, maxCnt, outFormat)

if __name__ == "__main__":
        main()
