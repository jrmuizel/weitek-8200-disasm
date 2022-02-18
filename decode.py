import sys

# Disassembler for Weitek XL-8236 + Weitek XL-8237 which combine to make the
# Weitek XL-8200.

# Based on http://www.bitsavers.org/components/weitek/XL/XL-8236_22-Bit_Raster_Code_Sequencer_Oct88.pdf
# and http://www.bitsavers.org/components/weitek/XL/XL-8237_32-Bit_Raster_Image_Processor_Oct88.pdf
verbose = False
some_code = open(sys.argv[1], "rb").read()

def sign_extend(x, width):
    if (x & (1<<(width - 1))):
        return -(((~x)&((1<<width)-1))+1)
    else:
        return x

def decode_8237(insn):
    rcs = insn >> 24
    if rcs == 0:
        return "transfer"
    elif rcs <= 3:
        return "long rcs" if verbose else ""
    elif rcs & 0b0010000:
        return "long rcs" if verbose else ""
    op = (insn >> 21) & 7
    if op == 0b100:
        ext = (insn >> 7) & 0xf
        cn = (insn >> 5) & 0x3
        rc = (insn >> 11) & 0x1f
        rb = insn & 0x1f
        imm5 = rb
        ra = (insn >> 16) & 0x1f
        if ext == 0b1100:
            return "c, ${} := ${} + {}".format(rc, ra, imm5)
        return ("arith", ext, cn, rc, ra, rb)
    elif op == 0b101:
        if (insn >> 10) & 1:
            # add signed immediate
            ra = (insn >> 16) & 0x1f
            rc = (insn >> 11) & 0x1f
            imm10 = sign_extend(insn & ((1<<10)-1), 10)
            return "${} := ${} + {}".format(rc, ra, imm10)
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
                rb = insn & 0x1f
                siz = (insn >> 11) & 3
                size = ["byte", "halfword", "tri-byte", "word"][siz]
                s = (insn >> 13) & 1
                sign = ["unsigned", "signed"][s]
                if is_store == 1:
                    e = (insn >> 15) & 1
                    if e:
                        return "mem[adr] := ${}".format(ra)
                    else:
                        return "mem[adr] := ${} align {} {}".format(rb, sign, size)
                else:
                    # Byte align for load data
                    return "${} := ${}[adr] align {} {}".format(ra, rb, sign, size)
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
            # load/store signed displacement, modify before
            return "adr := ${} := ${} + ({} << {})".format(rc, ra, sign_extend(imm5, 5), ixs)
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
        return ("subroutine call", hex(cfa + sign_extend(imm28, 28)))
    elif top3 == 0:
        next5 = (insn >> 24) & 0x3f
        if next5 == 0b00001:
            imm24 = insn & ((1<<24)-1)
            return("decrement stack and branch or pop if zero", imm24)
        elif next5 == 0b00110:
            return "continue" if verbose else ""
        elif next5 == 0b00010:
            imm24 = insn & ((1<<24)-1)
            return "branch {}".format(hex(cfa + imm24))
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
        elif next5 == 0b01001:
            return "Store RIP"
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
        return "${} := mem[adr]".format(rd)
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

