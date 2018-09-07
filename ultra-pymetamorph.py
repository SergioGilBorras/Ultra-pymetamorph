from __future__ import print_function

import argparse
import random
import time

import pefile
import os.path
from capstone import *
from keystone import *


class Pymetamorph(object):
    def __init__(self, file, debug=False):
        from capstone import x86_const
        self.NON_COMPILABLE_INSTRUCTION_IDS = [x86_const.X86_INS_RCR, x86_const.X86_INS_SAR, x86_const.X86_INS_SHL, x86_const.X86_INS_SHR]
        self.file = file
        self.debug = debug
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        self.cs.syntax = CS_OPT_SYNTAX_INTEL
	self.cs.skipdata_setup = ("db", None, None)
	self.cs.skipdata = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.ks.syntax = KS_OPT_SYNTAX_INTEL

	self.bytes_adds=0
	self.bytes_adds_AV=0
	
        self.instructions = []
        self.original_inst = []
	self.table_functions = set()
	self.table_ptr_rdata = set()
	self.table_addr_ret = set()
	self.table_ptr_jmp = list()
	self.table_ptr_cmpj = list()
	self.dead_code_table_load = [] 
	self.dead_code_table_find = [] 
	self.swap_code_table_load = []   
	if os.path.isfile(self.file):
            self.pe_handler = PEHandler(self.file)
            self.ImageBase = self.pe_handler.getImageBase()
            self.original_entry_point = self.pe_handler.getEntryPointAddress()
	    self.base_of_code = self.pe_handler.getBaseOfCodeAddress()
            self.code_section = self.pe_handler.findSection(self.original_entry_point)
            if self.code_section is None:
                raise Exception('unable to find .text section')
		exit()
	    self.code_size = self.code_section.Misc_VirtualSize
	    self.Inicio_code=self.ImageBase+self.base_of_code
	    self.Fin_code=self.ImageBase+self.base_of_code+self.code_size
	    self.raw_code = self.code_section.get_data()
	    self.load_list_intructions(self.raw_code)
	    self.tam_sobra = self.code_section.SizeOfRawData-self.code_section.Misc_VirtualSize
      
        else:
		print("The file error!!")
		exit()

	#self.print_header()

    def print_header(self): 
        if self.debug:
        	print(self.pe_handler.dump())
        	print('loading file')
	
	print("code_section:")
	print(self.code_section)
	
	print("entrypoint:")
	print(hex(self.original_entry_point),self.original_entry_point)
	print("ImageBase:")
	print(hex(self.ImageBase),self.ImageBase)
	    
	print("Inicio code:")
	print(hex(self.Inicio_code),self.Inicio_code)
	print("Fin code:")
	print(hex(self.Fin_code),self.Fin_code)
                
	print("code_size:")
	print(hex(self.get_code_size()),self.get_code_size())
	print("code_size:")
	print(hex(self.code_size),self.code_size)
	print("base_of_code:")
	print(hex(self.base_of_code),self.base_of_code)
	print("len raw_code:")
	print(hex(len(self.raw_code)),len(self.raw_code))
	print("len original_inst:")
	print(hex(len(self.original_inst)),len(self.original_inst))
	print("len instructions:")
	print(hex(len(self.instructions)),len(self.instructions))
	
	print("Misc_PhysicalAddress:")
	print(hex(self.code_section.Misc_PhysicalAddress),self.code_section.Misc_PhysicalAddress)
	
	print("Misc_VirtualSize:")
	print(hex(self.code_section.Misc_VirtualSize),self.code_section.Misc_VirtualSize)
	
	print("getSectionAligment:")
	print(hex(self.pe_handler.getSectionAligment()),self.pe_handler.getSectionAligment())

	print("PointerToRawData:")
	print(hex(self.code_section.PointerToRawData),self.code_section.PointerToRawData)
	print("VirtualAddress:")
	print(hex(self.code_section.VirtualAddress),self.code_section.VirtualAddress)


    def load_list_intructions(self, raw_code):
	
        self.instructions = []
        self.original_inst = []

	datacodeobj = self.getDataCodeObj(raw_code)
	ini_slice=0
	for sss in datacodeobj:
		fin_slice = sss.ofinicio
		for i in self.cs.disasm(raw_code[ini_slice:fin_slice], self.base_of_code+ini_slice):
			self.original_inst.append(i)
			inst = MetaIns(i)
			self.instructions.append(inst)
			ini_slice= sss.offin
		for i in sss.source:
			self.original_inst.append(i)
			inst = MetaIns(i)
			self.instructions.append(inst)
	for i in self.cs.disasm(raw_code[ini_slice:], self.base_of_code+ini_slice):
		self.original_inst.append(i)
		inst = MetaIns(i)
		self.instructions.append(inst)
	      

    def str_to_array_hex(self,strn):
	return map(lambda n: hex(ord(n)),strn)
	
    def str_to_int(self,strn):
	if isinstance(strn,int):
		return strn
	
	conta=1	
	num=0
	
	for n in str(strn):
		num+=(ord(n)*conta)
		conta*=256		
	return num

    def int_to_array_hex(self, inte):
	conta=16777216
	res=[0,0,0,0]
	if inte>conta:
		res[0]=hex(inte/conta)
		inte = inte%conta
	conta/=256
	
	if inte>conta:
		res[1]=hex(inte/conta)
		inte = inte%conta
	conta/=256
	
	if inte>conta:
		res[2]=hex(inte/conta)
		inte = inte%conta
	conta/=256
	
	if inte>conta:
		res[3]=hex(inte/conta)
		inte = inte%conta

	return res

    def int_to_str(self, inte):
	hexx = hex(inte)[2:]
	
	lenn = len(hexx)
	hexx = ("0"*(8-lenn))+hexx

	c="0x"
	res=""	
	for dd in range(4):
		res=chr(int(c+hexx[2*dd]+hexx[2*dd+1],16))+res
	
	return res

    def int_to_str_old(self, inte):
	conta=16777216
	res=""
	for i in range(3):
		if inte>conta:
			res=chr(inte/conta)+res
			inte = inte%conta
		else:
			res=chr(0)+res
		conta/=256
	res=chr(inte)+res
	
	return res

    def getDataCodeObj(self, raw_code):
	idx=0
	addr_r = 0
	addr_r_last = 0 
	ofaddr_r = 0
	ofaddr_r_last = 0 
	textstr = ""
	entra = False
	structDataInCode = None
	LstructDataInCode = list()
	
	for n in range(len(raw_code)):
		val=self.str_to_int(raw_code[(n):-(len(raw_code)-(n)-4)])
		if val>=self.Inicio_code and val<=self.Fin_code:

			addr_r = self.ImageBase+self.base_of_code+idx
			ofaddr_r = idx
			if addr_r_last+4 == addr_r:
				if not entra:
					structDataInCode = DataInCode()
					structDataInCode.inicio = addr_r_last
					structDataInCode.ofinicio = ofaddr_r_last
					structDataInCode.source.append(insn)
	
				insn2 = _cs_insn()
				insn2.id=0
				insn2.address=long(addr_r-self.ImageBase)
				insn2.size=4
				insn2.bytes=bytearray([raw_code[idx],raw_code[idx+1],raw_code[idx+2],raw_code[idx+3]])
				insn2.mnemonic = ".WORD"
				insn2.op_str="offset"
				structDataInCode.source.append(insn2)
	
				entra=True
			else:
				if structDataInCode!=None:
					structDataInCode.fin = addr_r_last+4
					structDataInCode.offin = ofaddr_r_last+4
					LstructDataInCode.append(structDataInCode)
					structDataInCode=None
				entra=False
	
			insn = _cs_insn()
			insn.id=0
			insn.address=long(addr_r-self.ImageBase)
			insn.size=4
			insn.bytes=bytearray([raw_code[idx],raw_code[idx+1],raw_code[idx+2],raw_code[idx+3]])
			insn.mnemonic = ".WORD"
			insn.op_str="offset"
			addr_r_last = addr_r
			ofaddr_r_last = ofaddr_r
		idx += 1
	if structDataInCode!=None:
		structDataInCode.fin = addr_r_last+4
		structDataInCode.offin = ofaddr_r_last+4
		LstructDataInCode.append(structDataInCode)
		structDataInCode=None
	return LstructDataInCode


    def write_file(self, filename):
      new_code = self.generate_binary_code()
      if new_code==self.raw_code:
	print("CODIGO NO MODIFICADO: No Write file...")

      else:
	
        if not self.pe_handler.writeBytes(self.code_section.PointerToRawData, new_code):
            raise Exception('Error write Bytes in text section')
       
	
	raw_file = self.pe_handler.get_data()
	f = open(filename,'wb+')
	f.write(raw_file)
	f.close()
	
	self.pe_handler = PEHandler(filename)

        self.pe_handler.sections()[0].Misc_VirtualSize = self.pe_handler.sections()[0].Misc_VirtualSize+self.bytes_adds
        self.pe_handler.sections()[0].Misc_PhysicalAddress = self.pe_handler.sections()[0].Misc_VirtualSize
        self.pe_handler.sections()[0].Misc = self.pe_handler.sections()[0].Misc_VirtualSize

	self.pe_handler.setEntryPointAddress(self.pe_handler.getEntryPointAddress()+self.bytes_adds_AV)

	self.pe_handler.generate_checksum()
        self.pe_handler.writeFile(filename)
	


    def dead_code_(self):
	
	tasm, num_i = self.ks.asm("lea esp,[esp]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea ebp,[ebp]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea esi,[esi]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea eax,[eax]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea ebx,[ebx]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea ecx,[ecx]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("lea edx,[edx]")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov eax,eax")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ebx,ebx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ecx,ecx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov edx,edx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ax,ax")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov bx,bx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov cx,cx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov dx,dx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ah,ah")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov bh,bh")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ch,ch")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov dh,dh")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov al,al")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov bl,bl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov cl,cl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov dl,dl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov ebp,ebp")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov esp,esp")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov esi,esi")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("mov edi,edi")
	self.dead_code_table_load.append(str(bytearray(tasm)))

	tasm, num_i = self.ks.asm("jmp +2")
	self.dead_code_table_load.append(str(bytearray(tasm)))
    
	tasm, num_i = self.ks.asm("xchg eax,eax")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ebx,ebx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ecx,ecx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg edx,edx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ax,ax")#NOP
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg bx,bx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg cx,cx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg dx,dx")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ah,ah")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg bh,bh")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ch,ch")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg dh,dh")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg al,al")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg bl,bl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg cl,cl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg dl,dl")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg ebp,ebp")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg esp,esp")
	self.dead_code_table_load.append(str(bytearray(tasm)))
	tasm, num_i = self.ks.asm("xchg esi,esi")
	self.dead_code_table_load.append(str(bytearray(tasm)))

	self.dead_code_table_load.append(str(bytearray([0xcc])))#INT3
	self.dead_code_table_load.append(str(bytearray([0x8d,0x49,0x0])))#LEA ECX,[ECX+0]
	self.dead_code_table_load.append(str(bytearray([0x8d,0x64,0x24,0x0])))#LEA ESP,[ESP+0]
	self.dead_code_table_load.append(str(bytearray([0x8d,0xa4,0x24,0x0,0x0,0x0,0x0])))#LEA ESP,[ESP+0]
	self.dead_code_table_load.append(str(bytearray([0x8d,0x9b,0x0,0x0,0x0,0x0])))#LEA EBX,[EBX+0]


    def dead_code_table(self):
        for idx,i in enumerate(self.instructions):
		if i.new_bytes in self.dead_code_table_load:
			self.dead_code_table_find.append(idx)			
	

    def generate_binary_code(self):
        code = ''
        for instruction in self.instructions:
            	if instruction.new_bytes is not None:
			code += instruction.new_bytes
        return str(code)

    def get_code_size(self):
        size = 01
        for inst in self.instructions:
            size += len(inst.new_bytes)
        return size

    def instruction_insert(self,pos_to_insert,insn):
      if self.tam_sobra<insn.size:
		print("FIN::SE ACABO EL HUECO!!!")
		return False
      elif self.instructions[pos_to_insert].original_inst.id==0:
		print("ERROR::NO SE PUEDE INSERTAR EN TABLAS NI EN POSICIONES REPETIDAS.")
		return True
      else:
	from capstone import x86_const
	
	self.original_inst.insert(pos_to_insert,insn)
	ins = MetaIns(insn)
	self.instructions.insert(pos_to_insert,ins)
	
	addr_to_insert=ins.new_addr
	Taddr_to_insert = addr_to_insert+self.ImageBase	
	self.tam_sobra=self.tam_sobra-insn.size
	
	for idx,i in enumerate(self.instructions):
		
		if idx>pos_to_insert:
			i.new_addr+=insn.size
			if i.original_inst.id!=0 and ((x86_const.X86_GRP_CALL in i.original_inst.groups) or (x86_const.X86_GRP_JUMP in i.original_inst.groups)) and i.original_inst.operands[0].imm>256 and (addr_to_insert>i.original_inst.operands[0].imm):
							
				if i.original_inst.size==6:				
				  	i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])-insn.size)

				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])!=85:
					if not(((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[2])-insn.size<0) or (x86_const.X86_GRP_CALL in i.original_inst.groups)):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])-insn.size)[0]
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])==85:
					zz=0
				elif i.original_inst.size==2:				
					if not((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[1])-insn.size<0):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])-insn.size)[0]
				else:
					i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])-insn.size)
				
		elif idx<pos_to_insert:
			if i.original_inst.id!=0 and ((x86_const.X86_GRP_CALL in i.original_inst.groups) or (x86_const.X86_GRP_JUMP in i.original_inst.groups)) and i.original_inst.operands[0].imm>256 and (addr_to_insert<i.original_inst.operands[0].imm):
				if i.original_inst.size==6:				
				  	i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])+insn.size)

				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])!=85:
					if not(((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[2])+insn.size<0) or (x86_const.X86_GRP_CALL in i.original_inst.groups)):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])+insn.size)[0]
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])==85:
					zz=0				
				elif i.original_inst.size==2:
					if not((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[1])+insn.size<0):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])+insn.size)[0]
				else:
					i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])+insn.size)

			
		if i.original_inst.id==0 and i.original_inst.mnemonic == ".WORD" and self.str_to_int(i.new_bytes)>=Taddr_to_insert:
			
			i.new_bytes=self.int_to_str(self.str_to_int(i.new_bytes)+insn.size)

		
		if i.original_inst.id!=0 and len(i.original_inst.operands)==1 and i.original_inst.operands[0].mem.disp>=Taddr_to_insert and i.original_inst.operands[0].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[0].mem.disp>=Taddr_to_insert and i.original_inst.operands[0].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[1].mem.disp>=Taddr_to_insert and i.original_inst.operands[1].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==1 and i.original_inst.operands[0].imm>=Taddr_to_insert and i.original_inst.operands[0].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[0].imm>=Taddr_to_insert and i.original_inst.operands[0].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[1].imm>=Taddr_to_insert and i.original_inst.operands[1].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_insert,insn.size)
		

		if not(i.original_inst.id==0 and i.original_inst.mnemonic == ".WORD"):
			for neinsn in self.cs.disasm(str(i.new_bytes),i.new_addr):
				i.original_inst=neinsn	

	
	self.update_addresses(Taddr_to_insert,insn.size)
	self.update_addresses_RVA(Taddr_to_insert,insn.size)


	conta=insn.size
	while conta>0:
		self.original_inst.pop()
		iii = self.instructions.pop()
		conta = conta-iii.original_inst.size
	while conta<0:
		insn2 = _cs_insn()
		insn2.id=0
		insn2.address=long(self.instructions[-1].original_addr+1)
		insn2.size=1
		insn2.bytes=bytearray([0])
		insn2.mnemonic = ".NULL"
		insn2.op_str=""
	
		self.original_inst.append(insn2)
        	ins2 = MetaIns(insn2)
		self.instructions.append(ins2)
		conta = conta + 1
		

	if self.pe_handler.getEntryPointAddress()>addr_to_insert:
		self.bytes_adds_AV+=insn.size

	self.bytes_adds+=insn.size

	return True

    def instruction_remove(self,pos_to_remove):
      if self.instructions[pos_to_remove].original_inst.id==0:
		print("ERROR::NO SE PUEDE BORRAR EN TABLAS NI EN POSICIONES REPETIDAS.")
      else:
	from capstone import x86_const
	
	insn = self.original_inst[pos_to_remove]
	self.original_inst.remove(insn)
	
	ins = self.instructions[pos_to_remove]
	self.instructions.remove(ins)

	addr_to_remove=ins.new_addr
	Taddr_to_remove=addr_to_remove+self.ImageBase

	self.tam_sobra=self.tam_sobra+insn.size


	for idx,i in enumerate(self.instructions):
		
		if idx>=pos_to_remove:
			i.new_addr-=insn.size
			if i.original_inst.id!=0 and ((x86_const.X86_GRP_CALL in i.original_inst.groups) or (x86_const.X86_GRP_JUMP in i.original_inst.groups)) and i.original_inst.operands[0].imm>256 and (addr_to_remove>i.original_inst.operands[0].imm):
			
				if i.original_inst.size==6:				
				  	i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])+insn.size)
					
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])!=85:
					if not(((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[2])+insn.size<0) or (x86_const.X86_GRP_CALL in i.original_inst.groups)):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])+insn.size)[0]
					
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])==85:
					zz=0
				elif i.original_inst.size==2:
					if not((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[1])+insn.size<0):
				
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])+insn.size)[0]
					
				else:
					i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])+insn.size)
					
	
		elif idx<pos_to_remove:
			if i.original_inst.id!=0 and ((x86_const.X86_GRP_CALL in i.original_inst.groups) or (x86_const.X86_GRP_JUMP in i.original_inst.groups)) and i.original_inst.operands[0].imm>256 and (addr_to_remove<i.original_inst.operands[0].imm):
				if i.original_inst.size==6:				
				  	i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])-insn.size)
					
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])!=85:
					if not(((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[2])-insn.size<0) or (x86_const.X86_GRP_CALL in i.original_inst.groups)):

						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+chr(self.str_to_int(i.new_bytes[1]))+self.int_to_str(self.str_to_int(i.new_bytes[2:])-insn.size)[0]
					
				elif i.original_inst.size==3 and self.str_to_int(i.new_bytes[1])==85:
					zz=0
				elif i.original_inst.size==2:
					
				    	if not((x86_const.X86_GRP_JUMP in i.original_inst.groups) and self.str_to_int(i.new_bytes[1])-insn.size<0):
						i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])-insn.size)[0]
					
	
				else:
					i.new_bytes=chr(self.str_to_int(i.new_bytes[0]))+self.int_to_str(self.str_to_int(i.new_bytes[1:])-insn.size)	
		

		if i.original_inst.id==0 and i.original_inst.mnemonic == ".WORD" and self.str_to_int(i.new_bytes)>Taddr_to_remove:
			
			i.new_bytes=self.int_to_str(self.str_to_int(i.new_bytes)-insn.size)

		
		if i.original_inst.id!=0 and len(i.original_inst.operands)==1 and i.original_inst.operands[0].mem.disp>=Taddr_to_remove and i.original_inst.operands[0].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[0].mem.disp>=Taddr_to_remove and i.original_inst.operands[0].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[1].mem.disp>=Taddr_to_remove and i.original_inst.operands[1].mem.disp<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==1 and i.original_inst.operands[0].imm>=Taddr_to_remove and i.original_inst.operands[0].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[0].imm>=Taddr_to_remove and i.original_inst.operands[0].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		elif i.original_inst.id!=0 and len(i.original_inst.operands)==2 and i.original_inst.operands[1].imm>=Taddr_to_remove and i.original_inst.operands[1].imm<=self.Fin_code:
			i.new_bytes=self.update_addresses_raw_code(i.new_bytes,Taddr_to_remove,-insn.size)
		

		if not(i.original_inst.id==0 and i.original_inst.mnemonic == ".WORD"):
			for neinsn in self.cs.disasm(str(i.new_bytes),i.new_addr):
				i.original_inst=neinsn
			
	
	
	self.update_addresses(Taddr_to_remove,-insn.size)
	self.update_addresses_RVA(Taddr_to_remove,-insn.size)


	conta=-insn.size
	while conta>0:		
		self.original_inst.pop()
		iii = self.instructions.pop()
		conta = conta-iii.original_inst.size

	while conta<0:
		insn2 = _cs_insn()
		insn2.id=0
		insn2.address=long(self.instructions[-1].original_addr+1)
		insn2.size=1
		insn2.bytes=bytearray([0])
		insn2.mnemonic = ".NULL"
		insn2.op_str=""
	
		self.original_inst.append(insn2)
        	ins2 = MetaIns(insn2)
		self.instructions.append(ins2)
		conta = conta + 1
		

	if self.pe_handler.getEntryPointAddress()>addr_to_remove:
		self.bytes_adds_AV-=insn.size

	self.bytes_adds-=insn.size


    def update_addresses_raw_code(self, code, addr_to_insert, size):
	lencode=len(code)
	for n in range(len(code)):
		val=self.str_to_int(code[n:n+4])		
		if val>=addr_to_insert and val<=self.Fin_code:
			code= code[:n]+self.int_to_str(val+size)+code[n+4:]

	return code

    def update_addresses(self, addr_to_insert, size):
	for sect in self.pe_handler.sections():
		if sect.Name!=".text\x00\x00\x00":
			code=sect.get_data()
			lencode=len(code)
			for n in range(len(code)/4):
				val=self.str_to_int(code[(4*n):-(lencode-(4*n)-4)])
				if val>=addr_to_insert and val<=self.Fin_code:
					code= code[:(4*n)]+self.int_to_str(val+size)+code[(4*n)+4:]

			if not self.pe_handler.writeBytes(sect.PointerToRawData, code):
				raise Exception('Error write Bytes in the section',sect.Name)
			

    def update_addresses_RVA(self, addr_to_insert, size):
	addr_to_insert-=self.ImageBase
	for sect in self.pe_handler.sections():
		if sect.Name==".rdata\x00\x00":
			code=sect.get_data()
			code_old=code
			lencode=len(code)
			for n in range(len(code)/4):
				val=self.str_to_int(code[(4*n):-(lencode-(4*n)-4)])
				if val-8==self.ImageBase+sect.VirtualAddress+(4*n):
					table_size=self.str_to_int(code[(4*(n+1)):-(lencode-(4*(n+1))-4)])
					for ts in range(table_size):
						vall = self.str_to_int(code[(4*(n+2+ts)):-(lencode-(4*(n+2+ts))-4)])
					
						if vall>=addr_to_insert and vall<=self.Fin_code:	
							code= code[:(4*(n+2+ts))]+self.int_to_str(vall+size)+code[(4*(n+2+ts))+4:]

					

			if not self.pe_handler.writeBytes(sect.PointerToRawData, code):
				raise Exception('Error write Bytes in the section',sect.Name)
	

    def __load_table_ptr_rdata(self):
	for sect in self.pe_handler.sections():
		if sect.Name==".rdata\x00\x00":
			code=sect.get_data()
			lencode=len(code)
			for n in range(len(code)/4):
				val=self.str_to_int(code[(4*n):-(lencode-(4*n)-4)])
				if val>=self.Inicio_code and val<=self.Fin_code:
					self.table_ptr_rdata.add(val)
					self.table_functions.add(val-self.ImageBase)
    
    def __load_table_ptr_data(self):
	for sect in self.pe_handler.sections():
		if sect.Name==".data\x00\x00\x00":
			code=sect.get_data()
			lencode=len(code)
			for n in range(len(code)/4):
				val=self.str_to_int(code[(4*n):-(lencode-(4*n)-4)])
				if val>=self.Inicio_code and val<=self.Fin_code:
					self.table_ptr_rdata.add(val)
					self.table_functions.add(val-self.ImageBase)

    def load_tables(self):
        from capstone import x86_const
	self.table_functions=set()
	self.table_functions.add(self.original_entry_point)
	self.table_addr_ret = set()
	self.table_ptr_jmp = list()
	self.table_ptr_cmpj = list()
	self.__load_table_ptr_rdata()
	self.__load_table_ptr_data()
	for i in self.instructions:
		i=i.original_inst
		if i.id!=0 and x86_const.X86_GRP_CALL in i.groups and i.operands[0].type==x86_const.X86_OP_IMM:
			self.table_functions.add(int(i.op_str,16))
		elif i.id!=0 and len(i.operands)==1 and i.operands[0].type==x86_const.X86_OP_IMM and i.operands[0].imm>=self.Inicio_code and i.operands[0].imm<=self.Fin_code:
			self.table_functions.add(int(i.operands[0].imm)-self.ImageBase)
		elif i.id!=0 and len(i.operands)==2 and i.operands[1].type==x86_const.X86_OP_IMM and i.operands[1].imm>=self.Inicio_code and i.operands[1].imm<=self.Fin_code:
			self.table_functions.add(int(i.operands[1].imm)-self.ImageBase)	
		elif i.id==266 and x86_const.X86_GRP_JUMP in i.groups:

			if i.operands[0].imm!=0: 
				self.table_ptr_jmp.append([i.address,int(i.operands[0].imm)])
			elif i.operands[0].mem.disp>=self.Inicio_code and i.operands[0].mem.disp<=self.Fin_code: 
				self.table_ptr_jmp.append([i.address,int(i.operands[0].mem.disp)])
		
		elif i.id!=0 and x86_const.X86_GRP_JUMP in i.groups:

			if i.operands[0].imm!=0: 
				self.table_ptr_cmpj.append([i.address,int(i.operands[0].imm)])
			elif i.operands[0].mem.disp>=self.Inicio_code and i.operands[0].mem.disp<=self.Fin_code: 
				self.table_ptr_cmpj.append([i.address,int(i.operands[0].mem.disp)])
		elif i.id!=0 and (x86_const.X86_GRP_RET in i.groups or x86_const.X86_GRP_IRET in i.groups):
			self.table_addr_ret.add(i.address)

	self.table_functions = sorted(self.table_functions)	

    def printfunctions(self):
	for addr in self.table_functions:
		print("sub_"+str(hex(self.ImageBase+addr))[2:])

class Object(object):
	pass

class DataInCode(object):
    def __init__(self):	
    	self.inicio = None
   	self.fin = None	
    	self.ofinicio = None
   	self.offin = None
    	self.source = list()
    def __repr__(self):
	return str(self.ofinicio)+" - "+str(self.offin)+" ** "+hex(self.inicio)+" - "+hex(self.fin) + "->" + str(self.source)

class _cs_insn(object):
    def __init__(self):
	self.id=None
	self.address=None
	self.size=None
	self.bytes=None
	self.mnemonic=None
	self.op_str=None
	self.details=None

class MetaIns(object):
    def __init__(self, original_inst, new_bytes=None, new_address=None):
        self.original_inst = original_inst
        self.original_addr = original_inst.address
        if new_address is None:
            self.new_addr = original_inst.address
        else:
            self.new_addr = new_address

        self.original_bytes = original_inst.bytes
        if new_bytes is None:
            self.new_bytes = original_inst.bytes
        else:
            self.new_bytes = new_bytes

    @property
    def size(self):
        return len(self.new_bytes)

class PEHandler(object):
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)

    def get_data(self):
	return self.pe.__data__

    def dump(self):
        return self.pe.dump_info()

    def getEntryPointAddress(self):
        return self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint

    def getBaseOfCodeAddress(self):
        return self.pe.OPTIONAL_HEADER.BaseOfCode

    def getImageBase(self):
        return self.pe.OPTIONAL_HEADER.ImageBase

    def findSection(self, address):
        for section in self.pe.sections:
            if section.contains_rva(address):
                return section
        return None

    def findSectionById(self, id):
        return self.pe.sections[id]

    def sections(self):
        return self.pe.sections

    def setBaseOfCode(self, new_code_pointer):
        self.pe.OPTIONAL_HEADER.BaseOfCode = new_code_pointer

    def setEntryPointAddress(self, new_entry_point):
        self.pe.NT_HEADERS.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point

    def getSectionAligment(self):
        return self.pe.OPTIONAL_HEADER.SectionAlignment

    def getSizeOfImage(self):
        return self.pe.OPTIONAL_HEADER.SizeOfImage

    def setSizeOfImage(self, size):
        self.pe.OPTIONAL_HEADER.SizeOfImage = size

    def writeBytes(self, offset, bytes):
        return self.pe.set_bytes_at_offset(offset, bytes)

    def writeFile(self, filename):
        self.pe.write(filename)

    def generate_checksum(self):
        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Pymetamorph: a metamorphic engine for Windows 32 bits executables made in python',
        epilog='if no optionals arguments are passed the default behavior is the same as '
               'pymetamorph.')
    parser.add_argument('input_file', type=str, help='The originals path to the executable file')
    parser.add_argument('output_file', type=str, help='The path of the new executable file')

    args = parser.parse_args()
    return args


def main():
    
    ini_time = time.time() 

    args = parse_args()
    meta = Pymetamorph(args.input_file)

    #meta.load_tables()
    #meta.printfunctions()
    meta.dead_code_()
    meta.dead_code_table()
    
    
    for idx, ide in enumerate(meta.dead_code_table_find):
	print("tam_sobra::",meta.tam_sobra,idx)		
	meta.instruction_remove(ide-idx)
	
	
    meta.dead_code_table_load.remove(str(bytearray([0xcc])))
	
    cont=True
    while meta.tam_sobra>0 and cont==True:
	print("tam_sobra::",meta.tam_sobra)
	ii= meta.dead_code_table_load[random.randint(0,len(meta.dead_code_table_load)-1)]		    	
	a=random.randint(3,len(meta.instructions)-(meta.tam_sobra))
	for insn in meta.cs.disasm(ii,meta.instructions[a].new_addr):
		
		cont=meta.instruction_insert(a, insn)	
		a=a+1

    meta.write_file(args.output_file)

    print("Tiempo: ", int(round((time.time()-ini_time)/60)),int(round((time.time()-ini_time)%60)))

if __name__ == '__main__':
    main()
