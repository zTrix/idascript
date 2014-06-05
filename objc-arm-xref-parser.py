#!/usr/bin/python

# From: https://github.com/intrepidusgroup/ocat
# Name: objc-arm-xref-parser.py
# Author: Ben Nell, Intrepidus Group
#
# This script is designed to parse through the IDA Pro database (IDB) for an 
# ARM Objective-C binary and build method-to-method cross references (xrefs).
# The basic technique is to parse through the "__objc_methanme" segment, find
# xrefs to every method name string that come from the "__objc_const" segment,
# and read function pointers out of the "const" structures. 
#
# This is a quick and dirty, unscientific approach. We're taking advantages of 
# the heavy lifting that IDA has already accomplished for us and using it to
# squeeze out some additional functionality.
#
# CAUTION: This script has the ability to mess up your IDB file in a ways that 
# you will not appreciate. Back up your IDB!

from idautils import *
from idc import *
from idaapi import *
from struct import unpack
from struct import pack

class ObjcMethod:
    """
    This is a simple helper class to assist in maintaining state.    
    """
    def __init__(self):
        self.methnmea = None
        self.constea = None
        self.selrefsea = None
        self.typeea = None
        self.codeea = None
        self.xrefs = list()
        self.methnmstr = ""

def get_segment_ranges():
    segments = {}
    for seg in Segments():
        segments[SegName(seg)] = seg
    return segments


def ea_get_refs(source_ea, filter_seg):
    """
    For a given source address, find all references that come from the specified
    segment "filter". Return a list of tuples containing the source address
    and the destination address.
    """
    ref_list = []
    refs = []
    for ref in DataRefsTo(source_ea):
        if filter_seg <= ref < SegEnd(filter_seg):
            refs.append(ref)
    if len(refs) > 0:
        for ref in refs:
            ref_list.append((source_ea, ref))
    return ref_list

def seg_get_refs(source_seg, filter_seg):
    """
    Using Heads(), find all "objects" that IDA has identified in a given 
    segement, and find references to each object that is sourced in the 
    "filter_seg" segment.
    """
    ref_list = []

    for head in Heads(source_seg, SegEnd(source_seg)):
        for ref_pair in ea_get_refs(head,filter_seg):
            ref_list.append(ref_pair)
    return ref_list

def get_code_ref(const_ea):
    """
    A simple function for pulling apart the "__objc_const" structures. Take in a
    pointer and return a dictionary containing references to a methname segment
    pointer, a methtype segment pointer, and a text segment pointer.
    """
    struct = {}
    struct['methname'] = Dword(const_ea)
    struct['methtype'] = Dword(const_ea+4)
    struct['methcode'] = Dword(const_ea+8)
    return struct

def build_refs():
    """
    This function implements the main functionality of the script. Check with 
    inline comments for specifics.
    """
    methods = []
    segments = get_segment_ranges()
    meth_seg = segments["__objc_methname"]
    const_seg = segments["__objc_const"]

    for meth_ref,const_ref in seg_get_refs(meth_seg, const_seg):

        # If our const address doesn't exist in the __objc_const segment, then
        # we're not looking at the type of method that we are trying to build
        # xrefs for in this script. 
        if not const_seg <= const_ref < SegEnd(const_seg):
            print "!!! const segment %x %x" % (meth_ref,const_ref)
            continue

        # Same goes for the location of our __objc_methname reference.
        elif not meth_seg <= meth_ref < SegEnd(meth_seg):
            print "!!! meth segment %x %x" % (meth_ref,const_ref)
            continue
        
        # Create a new ObjcMethod and populate it with the __objc_methname ptr
        # and the __objc_const ptr.
        meth = ObjcMethod()
        meth.methnmea,meth.constea = meth_ref,const_ref
        
        # Using the __objc_const pointer structure, parse out the location of
        # the code and the location of the method type. We may wish to use the
        # "type" pointer at a later point in time.
        const_struct = get_code_ref(meth.constea)

        # The code EA provided by the struct is off by 1.
        meth.codeea = const_struct['methcode']-1
        meth.typeea = const_struct['methtype']
        
        # If the identified code EA is bad, log and continue.
        if meth.codeea < 1:
            print "!!! 0x%x has an empty code ptr" % meth.constea
            continue

        # For easier readability, get the function name. If a function doesn't
        # exist at the destination (IDA analysis failed), just provide the code
        # EA.
        meth.methnmstr = GetFunctionName(meth.codeea)
        if not meth.methnmstr:
            print "!!! Fn doesn't exist at 0x%x. Subbing address" % meth.codeea
            meth.methnmstr = "0x%x" % meth.codeea

        # This is a totally non-scientific way of determining whether or not 
        # we're looking at a legitimate method object struct thing. If it
        # doesn't "point back to itself", ignor it and keep moving. What we're 
        # specifically worried about here is references to builtin methods.
        if meth.methnmea != const_struct['methname']:
            print "!!! not an objc2_meth object %x %x" % (meth.methnmea, 
                const_struct['methname'])
            continue
        
        # Search for a pointer coming from an entry in the __objc_selrefs
        # segment. This pointer, in turn, should have references from actual 
        # code.
        meth_selrefs = ea_get_refs(meth_ref,segments["__objc_selrefs"])

        # Debug? I don't believe that there should ever be >1, so we want to be
        # sure to catch it.
        if len(meth_selrefs) > 1:
            sys.exit("more than one selref per methname. unexpected-- abort.")
        
        # Debug. Alert that there was no selref and continue.
        elif len(meth_selrefs) < 1:
            print "!!! 0x%x has a constref but not selref" % meth_ref
            continue

        # Main functionality. If there is exactly one selrefs xerf, capture all
        # of the load instruction references to it coming from code (__text 
        # segment). We only want load instructions to avoid all of the noise
        # created by repeat references within close proximity of each other.
        else:
            meth.selrefsea = meth_selrefs[0][1]
            temp_xrefs = []
            for ref_pair in ea_get_refs(meth.selrefsea, segments["__text"]):
                if GetMnem(ref_pair[1])[:2] == "LD":
                    temp_xrefs.append(ref_pair[1])
                else:
                    continue
            meth.xrefs = temp_xrefs
            methods.append(meth)
        
    # Return a list of all identified methods.
    return methods

def upd_reg_comm(src, comment_str):
    """
    Given an address, retrieve any existing regular comments and append 
    comment data for the newly created comment, as this won't be auto-
    generated on the caller side.
    """
    # We're going to tag all of our comments with "OBJC_XREF" for clarity in
    # usage (as well as a quick way to find everything that we screwed up).
    new_comm = "OBJC_XREF %s"  % comment_str
    old_comm = GetCommentEx(src, 0)

    # If there's an existing comment, append our new comment instead of 
    # clobbering it.
    if old_comm:
        comm = "%s\n%s" % (old_comm, new_comm)
    else:
        comm = new_comm
    MakeComm(src, comm)

def xref_add(src, dst, comment_str=None):
    """
    Add a xref for a given source and destination and update the regular
    comment at the caller address to represent the change.
    """
    if comment_str:
        comment = "%s 0x%x" % (comment_str,dst)
    else:
        comment = "0x%x" % dst
    # To avoid getting ridiculous basic block formation, we're just using 
    # "fl_F", defined as "normal flow".
    #add_cref(src, dst, fl_CN)
    add_dref(src, dst, dr_R)
    upd_reg_comm(src,comment)

def main():
    # A count of xrefs that we're adding.
    xref_count = 0

    # We define some arrays to use for stat tracking. "build_refs()" should only
    # return references from load instructions, but I'm leaving this in here for
    # alternate use cases and/or debugging, if needed.
    ldrs =  []
    adds = []
    movs = []

    # In our specific application, I haven't witnessed any instructions that 
    # don't load, move, or add. Capture the oddballs, where applicable.
    oddballs = []

    for each in build_refs():
        print "Method: %s 0x%x - xrefs: %d" % (each.methnmstr, each.codeea, 
            len(each.xrefs))
        
        for ref in each.xrefs:
            # For stat-tracking, if desired.
            mnem = GetMnem(ref)
            if mnem[:2] == "LD":
                ldrs.append((ref,mnem))
            elif mnem[:3] == "MOV":
                movs.append((ref,mnem))
            elif mnem[:3] == "ADD":
                adds.append((ref,mnem))
            else:
                oddballs.append((ref,mnem))

            # Print the xref being built
            print "\t0x%x" % ref
            xref_add(ref,each.codeea,each.methnmstr)
            xref_count += 1

    #print "load instructions: %d" % len(ldrs)
    #print "add instructions: %d" % len(adds)
    #print "move instructions: %d" % len(movs)
    #print "unexpected instructions: %d" % len(oddballs)

    print "xrefs added: %d" % xref_count

if __name__ == '__main__':
    main()
