
"""
NPU22 - nonsense processing unit 2022

There are three types of operation:

Unary operators, operate on the contents of a single register.
Binary operators, operate on the cintents of two registers storing the result in the first.
Load/Store operations, these copy from memory to registers or to memory from registers. Each load/store uses two registers, one is the data loaded or stored, the other is the address.  Load/Store operations are masked as 1, 2 or 4 byte operations.

There are 16 registers, R14 is the flags register and R15 is the Program Counter, all other register allocations are determined by application. Registers are all 32bit.

Instructions are 16 bits:

Unary:

0000 00xx yyyy zzzz

000000 - opcode = unary op
xx - set z, if z conditional bits
yyyy - register address to operate on
zzzz - which unary operation to perform
  0000 Nop
  0001 Zero
  0010 Not
  0011
  
Binary:

0xxx xxyy zzzz aaaa

0 - top bit is zero for binary ops
xxxxx - operation
yy - set z, if z conditional bits
zzzz - dest register
aaaa - source register

Load/Store:

1xyy zzaa bbbb cccc

1 - top bit is always a 1 for load/store operations
x - 0 = load, 1 = store
yy - operation width
     00 = byte wide
     01 = 16 bit op
     10 = 32 bit op
     11 = reserved
zz - addressing mode
     00 = direct, reg cccc is the address
     01 = reserved
     10 = direct, pre-decrement, reg cccc is first decremented then used as the address
     11 = direct, post-increment, reg cccc is used as the address then cccc is incremented
aa - set z, if z conditional execution
bbbb - register holding data to be stored or loaded
cccc - address to store or load data to or from.

There are no special branching or stack instructions.  A jump is achieved by doing a load to the program counter.  Stack operations can be impemented using the predec and postinc addressing modes.

It is expected that interrupt implementation (if ever done) will use a shadow register set rather than stack operations.
"""

import re


class NPU:
  REG_FLAGS = 14
  FLAG_Z = (1<<0)
  FLAG_C = (1<<1)
  
  def __init__(self, memory):
    self.memory = memory
    self.regs = [0] * 16
    self.uops = [
      self._uop_nop,
      self._uop_not,
      self._uop_inc,
      self._uop_dec,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg,
      self._ex_usg
      ]
    self.bops = [
      self._op_cpy,
      self._op_add,
      self._op_sub,
      self._op_and,
      self._op_or,
      self._op_xor,
      self._op_shl,
      self._op_shr,
      ]
    while len(self.bops) < 31:
      self.bops.append(self._ex_usg)
  
  def clock(self):
    op = self.memory.read(self.regs[15], 1)
    self.regs[15] += 2
    
    if (op & 0x0100 == 0) or (self.regs[14] & FLAG_Z):
      if op & 0x0200:
        self.setz = True
      else:
        self.setz = False
      if op & 0xFC00 == 0:
        self.uops[op & 0xf]((op >> 4) & 0xf)
      elif op & 0x8000 == 0:
        self.bops[((op >> 10) & 0x1f)-1]((op >> 4) & 0xf, op & 0xf)
      else:
        ar = op & 0xf
        if op & 0x0c00 == 0x0800:
          self.regs[ar] -= 1
        
        if op & 0x4000 == 0:
          self.regs[(op >> 4) & 0xf] = self.memory.read(self.regs[ar], (op >> 12) & 0x3)
        else:
          self.memory.write(self.regs[(op>>4)&0xf], self.regs[ar], (op >>12)&0x3)
        
        if op & 0x0c00 == 0x0800:
          self.regs[ar] += 1
  
  def _update_flags(self, reg):
    if self.regs[reg] & ~0xffffffff:
      self.regs[self.REG_FLAGS] |= self.FLAG_C
    else:
      self.regs[self.REG_FLAGS] &= ~self.FLAG_C
    self.regs[reg] &= 0xffffffff
    if self.setz:
      if self.regs[reg] == 0:
        self.regs[self.REG_FLAGS] |= self.FLAG_Z
      else:
        self.regs[self.REG_FLAGS] &= ~self.FLAG_Z

  def _ex_usg(self, *args):
    raise Exception("Invalid op")
    
  def _uop_nop(self, reg):
    pass
  
  def _uop_not(self, reg):
    self.regs[reg] ^= 0xffffffff
    self._update_flags(reg)
    
  def _uop_inc(self, reg):
    self.regs[reg] += 1
    self._update_flags(reg)
  
  def _uop_dec(self, reg):
    self.regs[reg] -= 1
    self._update_flags(reg)
  
  def _op_cpy(self, dest, src):
    self.regs[dest] = self.regs[src]
    self._update_flags(dest)
    
  def _op_add(self, dest, src):
    self.regs[dest] += self.regs[src]
    self._update_flags(dest)
    
  def _op_sub(self, dest, src):
    self.regs[dest] -= self.regs[src]
    self._update_flags(dest)
    
  def _op_and(self, dest, src):
    self.regs[dest] &= self.regs[src]
    self._update_flags(dest)
    
  def _op_or(self, dest, src):
    self.regs[dest] |= self.regs[src]
    self._update_flags(dest)

  def _op_xor(self, dest, src):
    self.regs[dest] ^= self.regs[src]
    self._update_flags(dest)
  
  def _op_shr(self, dest, src):
    self.regs[dest] >>= self.regs[src]
    self._update_flags(dest)
    
  def _op_shl(self, dest, src):
    self.regs[dest] <<= self.regs[src]
    self._update_flags(dest)

class SimpleMemory:
  def __init__(self, size):
    self.data = [0] * size
  
  def read(self, addr, width):
    r = self.data[addr]
    if width > 0:
      r += (self.data[addr+1] << 8)
    if width > 1:
      r += (self.data[addr+2] << 16)
      r += (self.data[addr+3] << 24)
    return r
  
  def write(self, data, addr, width):
    self.data[addr] = data & 0xff
    if width > 0:
      self.data[addr+1] = (data >> 8) & 0xff
    if width > 1:
      self.data[addr+2] = (data >> 16) & 0xff
      self.data[addr+3] = (data >> 24) & 0xff

class NPAsm:
  def __init__(self):
    self._line_handlers = [
      {
        "re": re.compile(r'\w+:'),
        "cb": self._parse_label
      },
      {
        "re": re.compile(r'\s*(ifz)?\s*(\w+)\s+(\w+)\s*(sz)?'),
        "cb": self._parse_uop
      },
      {
        "re": re.compile(r'\s*(ifz)?\s*(\w+)\s+((?:ld)|(?:st))\.([bhl])\s+(\w+)\s+(\w+)\s*(sz)?'),
        "cb": self._parse_ldst
      },
      {
        "re": re.compile(r'\s*(ifz)?\s*(\w+)\s+(\w+)\s+(\w+)\s*(sz)?'),
        "cb": self._parse_bop
      }
    ]
    self.pc = 0
  
  def parse(self, lines):
    for line in lines:
      line = line.split("//")[0]
      if line.strip():
        for r in self._line_handlers:
          m = r["re"].match(line)
          if m:
            r["cb"](m)
            break
        else:
          raise Exception("unhandled syntax at {}".format(line))
          
  def _parse_label(self, m):
    print("Found label {} at {}".format(m.group(1), self.pc))
  
  def _parse_uop(self, m):
    print("Found unary operation {}".format(m.group(2)))
    
    self.pc += 2
  
  def _parse_ldst(self, m):
    print("Found load/store op {}.{}".format(m.group(2), m.group(3)))
    self.pc += 2
  
  def _parse_bop(self, m):
    print("Found binary op {}".format(m.group(2)))
    self.pc += 2
    
if __name__ == "__main__":
  m = SimpleMemory(1024)
  n = NPU(m)
  
  code = """
  inc r0
  add r1 r0
  inc r0
  add r1 r0
  """
  
  npa = NPAsm()
  npa.parse(code.splitlines())
  
  m.write(0x0002, 0, 1)
  m.write(0x0810, 2, 1)
  m.write(0x0002, 4, 1)
  m.write(0x0810, 6, 1)
  m.write(0x000f, 8, 1)
  
  while True:
    n.clock()
    print(n.regs)