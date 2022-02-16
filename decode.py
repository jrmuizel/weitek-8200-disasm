import sys

# Disassembler for Weitek XL-8236 + Weitek XL-8237 which combine to make the
# Weitek XL-8200.

# Based on http://www.bitsavers.org/components/weitek/XL/XL-8236_22-Bit_Raster_Code_Sequencer_Oct88.pdf
# and http://www.bitsavers.org/components/weitek/XL/XL-8237_32-Bit_Raster_Image_Processor_Oct88.pdf

some_code = open(sys.argv[1], "rb").read()
def decode_8237(insn):
    rcs = insn >> 24
    if rcs == 0:
        return "transfer"
    elif rcs <= 3:
        return "long rcs"
    elif rcs & 0b0010000:
        return "long rcs"
    op = (insn >> 21) & 7
    if op == 0b100:
        return "arith"
    elif op == 0b101:
        if (insn >> 10) & 1:
            return "add signed immediate"
        else:
            return "logical"
    elif op == 0b000:
        ra = (insn >> 16) & 0x1f
        length = (insn >> 11) & 0x1f
        shf = (insn >> 6) & 0x1f
        m = (insn >> 5) & 1
        rb = insn & 0x1f
        if m == 0:
            return "{} := deposit {} {} {}".format(ra, rb, shf, length)
        else:
            return "{} := {} deposit {} {} {}".format(ra, ra, rb, shf, length)

    elif op == 0b001:
        if (insn >> 5) & 1:
            return "merge immediate"
        else:
            return "extract"
    elif op == 0b100:
        return "dynamic extract/deposit/merge"
    elif op == 0b011:
        ra = (insn >> 16) & 0x1f
        imm16 = insn & 0xffff
        return "${} := ${} deposit {}".format(ra, ra, imm16)
        return "merge halfword high"
    elif op == 0b111:
        ext = (insn >> 7) & 0x7
        ra = (insn >> 16) & 0x1f
        rc = (insn >> 11) & 0x1f
        imm5 = insn & 0x1f
        ixs = (insn >> 5) & 3
        if ext == 0b111:
            op2 = (insn >> 5) & 0x3
            if op2 == 0b01:
                return "bitwise merge"
            elif op2 == 0b10:
                return "perfect exchange"
            elif op2 == 0b00:
                is_store = (insn >> 14) & 1
                ra = (insn >> 16) & 0x1f
                if is_store == 1:
                    return ("byte align store", ra)
                else:
                    return ("byte align load", ra)
            elif op2 == 0b11:
                ext = (insn >> 11) & 0x1f
                if ext == 0b11101:
                    return "swap register banks"
                elif ext == 0b10001:
                    return "${} := adr".format(ra)
                return ("multiply/divide/priority encode/housekeeping", ra, ext)
        elif ext == 0b000:
            return "load/store indexed, modify after"
        elif ext == 0b001:
            return "load/store signed displacement, modify after"
        elif ext == 0b010:
            return "load/store indexed, modify before"
        elif ext == 0b011:
            return "adr := ${} := ${} + ({} << {})".format(rc, ra, imm5, ixs)
        else:
            return ("load/store address with index/signed displacement", ext)
    elif op == 0b110:
        ra = (insn >> 16) & 0x1f
        imm16 = insn & 0xffff
        return "adr := ${} + {}".format(ra, imm16)
    elif op == 0b010:
        ra = (insn >> 16) & 0x1f
        imm16 = insn & 0xffff
        return "${} := sign_extend({})".format(ra, imm16)
    else:
        return "unknown"


def decode_8236(insn):
    top3 = (insn >> 29)
    top4 = (insn >> 28)
    if top4 == 1:
        imm28 = insn & ((1<<28)-1)
        return ("subroutine call", hex(cfa + imm28))
    elif top3 == 0:
        next5 = (insn >> 24) & 0x3f
        if next5 == 0b00001:
            imm24 = insn & ((1<<24)-1)
            return("decrement stack and branch or pop if zero", imm24)
        elif next5 == 0b00110:
            return("continue")
        elif next5 == 0b00010:
            imm24 = insn & ((1<<24)-1)
            return("branch", hex(cfa + imm24))
        elif next5 == 0:
            next3 = (insn >> (16 + 5)) & 7
            if next3 == 0b001:
                return("transfer word from RIP to RCS internal register")
            elif next3 == 0b000:
                ra = (insn >> 16) & 0b11111
                if ((insn >> 11) & 0b11111) != 0:
                    return(((insn >> 11) & 0b11111))
                    assert(((insn >> 11) & 0b11111) == 0)
                return("push RIP register onto stack", ra)
            elif next3 == 0b011:
                return("Transfer word from RCS internal register to RIP")
            else:
                return("data transfer", next3)
            ext = (insn >> 11) & 0x3f
            if ext == 0b00101:
                return("return from interrupt")
        elif next5 == 0b01011:
            return("override neutralization")
        elif next5 == 0b01101:
            return "subroutine return"
        elif next5 == 0b01111:
            return "Override neutralization of subroutine call shadow"
        elif next5 == 0b00101:
            return "reverse neutralization"
        else:
            return("bad", next5)
    elif top3 == 0b100:
        imm5 = (insn >> 24) & 0x3f
        return("short branch", imm5)
    elif top3 == 0b001:
        imm5 = (insn >> 24) & 0x3f
        return("decrement stack and backward branch or pop if zero", imm5)
    elif top3 == 0b010 or top3 == 0b011:
        imm5 = (insn >> 24) & 0x3f
        return("short forward branch on condition", hex(cfa + imm5))
    elif top3 == 0b101:
        return("store coprocessor")
    elif top3 == 0b110:
        rd = (insn >> 24) & 0x3f
        return("load RIP", rd)
    elif top3 == 0b111:
        rd = (insn >> 24) & 0x3f
        return("load coprocessor", rd)
    else:
        return(top3)

cfa = 0
for a, b, c, d in zip(*[iter(some_code)]*4): 
    #insn = a << 24 | b << 16 | c << 8 | d
    insn = d << 24 | c << 16 | b << 8 | a
    print("{:x} {:#010x} {}, {}".format(cfa, insn, decode_8236(insn), decode_8237(insn)))
    cfa += 1
