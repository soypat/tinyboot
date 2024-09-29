package xelf

// Version is found in Header.Ident[EI_VERSION] and Header.Version.
//
//go:generate stringer -linecomment -output=stringers.go -type=Class,Data,OSABI,Type,Machine,SectionIndex,ProgType,sectionFlag,progFlag,NType,SymVis,SymBind,SymType,RX86_64,RAARCH64,RAlpha,RARM,R386,RMIPS,RLoongArch,RPPC,RPPC64,RRISCV

// Version is found in [Header].
type Version byte

const (
	VersionNone    Version = 0 // None
	VersionCurrent Version = 1 // Current
)

type Class uint8

const (
	ClassNone Class = iota // unknown class
	Class32                // 32-bit architecture
	Class64                // 64-bit architecture
)

type Data uint8

const (
	DataNone Data = iota // unknown data format
	Data2LSB             // 2's complement little-endian
	Data2MSB             // 2's complement big-endian
)

func (d Data) Validate() error {
	if d != Data2LSB && d != Data2MSB {
		return makeFormatErr(offData, "unknown data encoding", d)
	}
	return nil
}

// OSABI is the operating system (OS) application binary interface (ABI)
type OSABI uint8

const (
	OSABINone       OSABI = 0   // UNIX System V ABI
	OSABIHPUX       OSABI = 1   // HP-UX operating system
	OSABINetBSD     OSABI = 2   // NetBSD
	OSABILinux      OSABI = 3   // Linux
	OSABIHurd       OSABI = 4   // Hurd
	OSABI86Open     OSABI = 5   // 86Open common IA32 ABI
	OSABISolaris    OSABI = 6   // Solaris
	OSABIAIX        OSABI = 7   // AIX
	OSABIIRIX       OSABI = 8   // IRIX
	OSABIFreeBSD    OSABI = 9   // FreeBSD
	OSABITRU64      OSABI = 10  // TRU64 UNIX
	OSABIModesto    OSABI = 11  // Novell Modesto
	OSABIOpenBSD    OSABI = 12  // OpenBSD
	OSABIOpenVMS    OSABI = 13  // Open VMS
	OSABINSK        OSABI = 14  // HP Non-Stop Kernel
	OSABIAROS       OSABI = 15  // Amiga Research OS
	OSABIFenixOS    OSABI = 16  // The FenixOS highly scalable multi-core OS
	OSABICloudBI    OSABI = 17  // Nuxi CloudABI
	OSABIARM        OSABI = 97  // ARM
	OSABIStandalone OSABI = 255 // Standalone (embedded) application
)

// Type is the ELF header's type.
type Type uint16

const (
	TypeNone        Type = 0      // Unknown type
	TypeRelocatable Type = 1      // Relocatable
	TypeExecutable  Type = 2      // Executable
	TypeDynamic     Type = 3      // Shared object
	TypeCore        Type = 4      // Core file
	TypeOSlo        Type = 0xfe00 // First operating system specific
	TypeOShi        Type = 0xfeff // Last operating system-specific
	TypeProclo      Type = 0xff00 // First processor-specific
	TypeProchi      Type = 0xffff // Last processor-specific
)

// Machine is in the ELF's header. Specifies the target computer.
type Machine uint16

const (
	MachineNone          Machine = 0   // Unknown machine
	MachineM32           Machine = 1   // AT&T WE32100
	MachineSPARC         Machine = 2   // Sun SPARC
	Machine386           Machine = 3   // Intel i386
	Machine68K           Machine = 4   // Motorola 68000
	Machine88K           Machine = 5   // Motorola 88000
	Machine860           Machine = 7   // Intel i860
	MachineMIPS          Machine = 8   // MIPS R3000 Big-Endian only
	MachineS370          Machine = 9   // IBM System/370
	MachineMIPS_RS3_LE   Machine = 10  // MIPS R3000 Little-Endian
	MachinePARISC        Machine = 15  // HP PA-RISC
	MachineVPP500        Machine = 17  // Fujitsu VPP500
	MachineSPARC32plus   Machine = 18  // SPARC v8plus
	Machine960           Machine = 19  // Intel 80960
	MachinePPC           Machine = 20  // PowerPC 32-bit
	MachinePPC64         Machine = 21  // PowerPC 64-bit
	MachineS390          Machine = 22  // IBM System/390
	MachineV800          Machine = 36  // NEC V800
	MachineFR20          Machine = 37  // Fujitsu FR20
	MachineRH32          Machine = 38  // TRW RH-32
	MachineRCE           Machine = 39  // Motorola RCE
	MachineARM           Machine = 40  // ARM
	MachineSH            Machine = 42  // Hitachi SH
	MachineSPARCV9       Machine = 43  // SPARC v9 64-bit
	MachineTriCore       Machine = 44  // Siemens TriCore embedded processor
	MachineARC           Machine = 45  // Argonaut RISC Core
	MachineH8_300        Machine = 46  // Hitachi H8/300
	MachineH8_300H       Machine = 47  // Hitachi H8/300H
	MachineH8S           Machine = 48  // Hitachi H8S
	MachineH8_500        Machine = 49  // Hitachi H8/500
	MachineIA_64         Machine = 50  // Intel IA-64 Processor
	MachineMIPS_X        Machine = 51  // Stanford MIPS-X
	MachineColdFire      Machine = 52  // Motorola ColdFire
	Machine68HC12        Machine = 53  // Motorola M68HC12
	MachineMMA           Machine = 54  // Fujitsu MMA
	MachinePCP           Machine = 55  // Siemens PCP
	MachineNCPU          Machine = 56  // Sony nCPU
	MachineNDR1          Machine = 57  // Denso NDR1 microprocessor
	MachineStarCore      Machine = 58  // Motorola Star*Core processor
	MachineME16          Machine = 59  // Toyota ME16 processor
	MachineST100         Machine = 60  // STMicroelectronics ST100 processor
	MachineTinyJ         Machine = 61  // Advanced Logic Corp. TinyJ processor
	MachineX86_64        Machine = 62  // Advanced Micro Devices x86-64
	MachinePDSP          Machine = 63  // Sony DSP Processor
	MachinePDP10         Machine = 64  // Digital Equipment Corp. PDP-10
	MachinePDP11         Machine = 65  // Digital Equipment Corp. PDP-11
	MachineFX66          Machine = 66  // Siemens FX66 microcontroller
	MachineST9PLUS       Machine = 67  // STMicroelectronics ST9+ 8/16 bit microcontroller
	MachineST7           Machine = 68  // STMicroelectronics ST7 8-bit microcontroller
	Machine68HC16        Machine = 69  // Motorola MC68HC16 Microcontroller
	Machine68HC11        Machine = 70  // Motorola MC68HC11 Microcontroller
	Machine68HC08        Machine = 71  // Motorola MC68HC08 Microcontroller
	Machine68HC05        Machine = 72  // Motorola MC68HC05 Microcontroller
	MachineSVX           Machine = 73  // Silicon Graphics SVx
	MachineST19          Machine = 74  // STMicroelectronics ST19 8-bit microcontroller
	MachineVAX           Machine = 75  // Digital VAX
	MachineCRIS          Machine = 76  // Axis Communications 32-bit embedded processor
	MachineJavelin       Machine = 77  // Infineon Technologies 32-bit embedded processor
	MachineFirepath      Machine = 78  // Element 14 64-bit DSP Processor
	MachineZSP           Machine = 79  // LSI Logic 16-bit DSP Processor
	MachineMMIX          Machine = 80  // Donald Knuth's educational 64-bit processor
	MachineHUANY         Machine = 81  // Harvard University machine-independent object files
	MachinePrism         Machine = 82  // SiTera Prism
	MachineAVR           Machine = 83  // Atmel AVR 8-bit microcontroller
	MachineFR30          Machine = 84  // Fujitsu FR30
	MachineD10V          Machine = 85  // Mitsubishi D10V
	MachineD30V          Machine = 86  // Mitsubishi D30V
	MachineV850          Machine = 87  // NEC v850
	MachineM32R          Machine = 88  // Mitsubishi M32R
	MachineMN10300       Machine = 89  // Matsushita MN10300
	MachineMN10200       Machine = 90  // Matsushita MN10200
	MachinePJ            Machine = 91  // picoJava
	MachineOPENRISC      Machine = 92  // OpenRISC 32-bit embedded processor
	MachineARC_Compact   Machine = 93  // ARC International ARCompact processor (old spelling/synonym: MachineARC_A5)
	MachineXtensa        Machine = 94  // Tensilica Xtensa Architecture
	MachineVideoCore     Machine = 95  // Alphamosaic VideoCore processor
	MachineTMM_GPP       Machine = 96  // Thompson Multimedia General Purpose Processor
	MachineNS32K         Machine = 97  // National Semiconductor 32000 series
	MachineTPC           Machine = 98  // Tenor Network TPC processor
	MachineSNP1K         Machine = 99  // Trebia SNP 1000 processor
	MachineST200         Machine = 100 // STMicroelectronics (www.st.com) ST200 microcontroller
	MachineIP2K          Machine = 101 // Ubicom IP2xxx microcontroller family
	MachineMAX           Machine = 102 // MAX Processor
	MachineCR            Machine = 103 // National Semiconductor CompactRISC microprocessor
	MachineF2MC16        Machine = 104 // Fujitsu F2MC16
	MachineMSP430        Machine = 105 // Texas Instruments embedded microcontroller msp430
	MachineBlackfin      Machine = 106 // Analog Devices Blackfin (DSP) processor
	MachineSE_C33        Machine = 107 // S1C33 Family of Seiko Epson processors
	MachineSEP           Machine = 108 // Sharp embedded microprocessor
	MachineArca          Machine = 109 // Arca RISC Microprocessor
	MachineUNICORE       Machine = 110 // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
	MachineEXcess        Machine = 111 // eXcess: 16/32/64-bit configurable embedded CPU
	MachineDXP           Machine = 112 // Icera Semiconductor Inc. Deep Execution Processor
	MachineAlteraNios2   Machine = 113 // Altera Nios II soft-core processor
	MachineCRX           Machine = 114 // National Semiconductor CompactRISC CRX microprocessor
	MachineXGATE         Machine = 115 // Motorola XGATE embedded processor
	MachineC166          Machine = 116 // Infineon C16x/XC16x processor
	MachineM16C          Machine = 117 // Renesas M16C series microprocessors
	MachineDSPIC30F      Machine = 118 // Microchip Technology dsPIC30F Digital Signal Controller
	MachineCE            Machine = 119 // Freescale Communication Engine RISC core
	MachineM32C          Machine = 120 // Renesas M32C series microprocessors
	MachineTSK3000       Machine = 131 // Altium TSK3000 core
	MachineRS08          Machine = 132 // Freescale RS08 embedded processor
	MachineSHARC         Machine = 133 // Analog Devices SHARC family of 32-bit DSP processors
	MachineECOG2         Machine = 134 // Cyan Technology eCOG2 microprocessor
	MachineSCORE7        Machine = 135 // Sunplus S+core7 RISC processor
	MachineDSP24         Machine = 136 // New Japan Radio (NJR) 24-bit DSP Processor
	MachineVideoCore3    Machine = 137 // Broadcom VideoCore III processor
	MachineLATTICEMICO32 Machine = 138 // RISC processor for Lattice FPGA architecture
	MachineSE_C17        Machine = 139 // Seiko Epson C17 family
	MachineTI_C6000      Machine = 140 // The Texas Instruments TMS320C6000 DSP family
	MachineTI_C2000      Machine = 141 // The Texas Instruments TMS320C2000 DSP family
	MachineTI_C5500      Machine = 142 // The Texas Instruments TMS320C55x DSP family
	MachineTI_ARP32      Machine = 143 // Texas Instruments Application Specific RISC Processor, 32bit fetch
	MachineTI_PRU        Machine = 144 // Texas Instruments Programmable Realtime Unit
	MachineMMDSPPlus     Machine = 160 // STMicroelectronics 64bit VLIW Data Signal Processor
	MachineCypressM8C    Machine = 161 // Cypress M8C microprocessor
	MachineR32C          Machine = 162 // Renesas R32C series microprocessors
	MachineTriMedia      Machine = 163 // NXP Semiconductors TriMedia architecture family
	MachineQDSP6         Machine = 164 // QUALCOMM DSP6 Processor
	Machine8051          Machine = 165 // Intel 8051 and variants
	MachineSTXP7X        Machine = 166 // STMicroelectronics STxP7x family of configurable and extensible RISC processors
	MachineNDS32         Machine = 167 // Andes Technology compact code size embedded RISC processor family
	MachineECOG1         Machine = 168 // Cyan Technology eCOG1X family
	MachineECOG1X        Machine = 168 // Cyan Technology eCOG1X family
	MachineMAXQ30        Machine = 169 // Dallas Semiconductor MAXQ30 Core Micro-controllers
	MachineXIMO16        Machine = 170 // New Japan Radio (NJR) 16-bit DSP Processor
	MachineMANIK         Machine = 171 // M2000 Reconfigurable RISC Microprocessor
	MachineCrayNV2       Machine = 172 // Cray Inc. NV2 vector architecture
	MachineRX            Machine = 173 // Renesas RX family
	MachineMETAG         Machine = 174 // Imagination Technologies META processor architecture
	MachineMCSTElbrus    Machine = 175 // MCST Elbrus general purpose hardware architecture
	MachineECOG16        Machine = 176 // Cyan Technology eCOG16 family
	MachineCR16          Machine = 177 // National Semiconductor CompactRISC CR16 16-bit microprocessor
	MachineETPU          Machine = 178 // Freescale Extended Time Processing Unit
	MachineSLE9X         Machine = 179 // Infineon Technologies SLE9X core
	MachineL10M          Machine = 180 // Intel L10M
	MachineK10M          Machine = 181 // Intel K10M
	MachineAARCH64       Machine = 183 // ARM 64-bit Architecture (AArch64)
	MachineAVR32         Machine = 185 // Atmel Corporation 32-bit microprocessor family
	MachineSTM8          Machine = 186 // STMicroeletronics STM8 8-bit microcontroller
	MachineTILE64        Machine = 187 // Tilera TILE64 multicore architecture family
	MachineTILEPro       Machine = 188 // Tilera TILEPro multicore architecture family
	MachineMicroBlaze    Machine = 189 // Xilinx MicroBlaze 32-bit RISC soft processor core
	MachineCUDA          Machine = 190 // NVIDIA CUDA architecture
	MachineTILEGx        Machine = 191 // Tilera TILE-Gx multicore architecture family
	MachineCloudShield   Machine = 192 // CloudShield architecture family
	MachineCOREA_1ST     Machine = 193 // KIPO-KAIST Core-A 1st generation processor family
	MachineCOREA_2ND     Machine = 194 // KIPO-KAIST Core-A 2nd generation processor family
	MachineARC_COMPACT2  Machine = 195 // Synopsys ARCompact V2
	MachineOpen8         Machine = 196 // Open8 8-bit RISC soft processor core
	MachineRL78          Machine = 197 // Renesas RL78 family
	MachineVideoCore5    Machine = 198 // Broadcom VideoCore V processor
	Machine78KOR         Machine = 199 // Renesas 78KOR family
	Machine56800EX       Machine = 200 // Freescale 56800EX Digital Signal Controller (DSC)
	MachineBA1           Machine = 201 // Beyond BA1 CPU architecture
	MachineBA2           Machine = 202 // Beyond BA2 CPU architecture
	MachineXCORE         Machine = 203 // XMOS xCORE processor family
	MachineMCHP_PIC      Machine = 204 // Microchip 8-bit PIC(r) family
	MachineIntel205      Machine = 205 // Reserved by Intel
	MachineIntel206      Machine = 206 // Reserved by Intel
	MachineIntel207      Machine = 207 // Reserved by Intel
	MachineIntel208      Machine = 208 // Reserved by Intel
	MachineIntel209      Machine = 209 // Reserved by Intel
	MachineKM32          Machine = 210 // KM211 KM32 32-bit processor
	MachineKMX32         Machine = 211 // KM211 KMX32 32-bit processor
	MachineKMX16         Machine = 212 // KM211 KMX16 16-bit processor
	MachineKMX8          Machine = 213 // KM211 KMX8 8-bit processor
	MachineKVARC         Machine = 214 // KM211 KVARC processor
	MachineCDP           Machine = 215 // Paneve CDP architecture family
	MachineCOGE          Machine = 216 // Cognitive Smart Memory Processor
	MachineCool          Machine = 217 // Bluechip Systems CoolEngine
	MachineNORC          Machine = 218 // Nanoradio Optimized RISC
	MachineCSR_KALIMBA   Machine = 219 // CSR Kalimba architecture family
	MachineZ80           Machine = 220 // Zilog Z80
	MachineVISIUM        Machine = 221 // Controls and Data Services VISIUMcore processor
	MachineFT32          Machine = 222 // FTDI Chip FT32 high performance 32-bit RISC architecture
	MachineMoxie         Machine = 223 // Moxie processor family
	MachineAMDGPU        Machine = 224 // AMD GPU architecture
	MachineRISCV         Machine = 243 // RISC-V
	MachineLanai         Machine = 244 // Lanai 32-bit processor
	MachineBPF           Machine = 247 // Linux BPF – in-kernel virtual machine
	MachineLoongArch     Machine = 258 // LoongArch

	// Non-standard or deprecated.
	Machine486         Machine = 6      // Intel i486
	MachineMIPS_RS4_BE Machine = 10     // MIPS R4000 Big-Endian
	MachineAlpha_STD   Machine = 41     // Digital Alpha (standard value)
	MachineAlpha       Machine = 0x9026 // Alpha (written in the absence of an ABI)
)

// Special section indices.
type SectionIndex int

const (
	SecIdxUndef     SectionIndex = 0      // Undefined, missing, irrelevant
	SecIdxReserveLo SectionIndex = 0xff00 // First of reserved range
	SecIdxProcLo    SectionIndex = 0xff00 // First processor-specific
	SecIdxProcHi    SectionIndex = 0xff1f // Last processor-specific
	SecIdxOSLo      SectionIndex = 0xff20 // First operating system-specific
	SecIdxOSHi      SectionIndex = 0xff3f // Last operating system-specific
	SecIdxAbs       SectionIndex = 0xfff1 // Absolute values
	SecIdxCommon    SectionIndex = 0xfff2 // Common data
	SecIdxXindex    SectionIndex = 0xffff // Escape; index stored elsewhere
	SecIdxReserveHi SectionIndex = 0xffff // Last of reserved range
)

// Section type.
type SectionType uint32

const (
	SecTypeNull          SectionType = 0          // inactive
	SecTypeProgBits      SectionType = 1          // program defined information
	SecTypeSymTab        SectionType = 2          // symbol table section
	SecTypeStrTab        SectionType = 3          // string table section
	SecTypeRelA          SectionType = 4          // relocation section with addends
	SecTypeHash          SectionType = 5          // symbol hash table section
	SecTypeDynamic       SectionType = 6          // dynamic section
	SecTypeNote          SectionType = 7          // note section
	SecTypeNobits        SectionType = 8          // no space section
	SecTypeRel           SectionType = 9          // relocation section - no addends
	SecTypeSHLib         SectionType = 10         // reserved - purpose unknown
	SecTypeDynSym        SectionType = 11         // dynamic symbol table section
	SecTypeInitArray     SectionType = 14         // Initialization function pointers
	SecTypeFiniArray     SectionType = 15         // Termination function pointers
	SecTypePreinitArray  SectionType = 16         // Pre-initialization function ptrs
	SecTypeGroup         SectionType = 17         // Section group
	SecTypeSymTab_SHNDX  SectionType = 18         // Section indexes (see SHN_XINDEX)
	SecTypeOSLo          SectionType = 0x60000000 // First of OS specific semantics
	SecTypeGNUAttributs  SectionType = 0x6ffffff5 // GNU object attributes
	SecTypeGNUHash       SectionType = 0x6ffffff6 // GNU hash table
	SecTypeGNULibList    SectionType = 0x6ffffff7 // GNU prelink library list
	SecTypeGNUVerDef     SectionType = 0x6ffffffd // GNU version definition section
	SecTypeGNUVerNeed    SectionType = 0x6ffffffe // GNU version needs section
	SecTypeGNUVerSym     SectionType = 0x6fffffff // GNU version symbol table
	SecTypeOSHi          SectionType = 0x6fffffff // Last of OS specific semantics
	SecTypeProcLo        SectionType = 0x70000000 // reserved range for processor
	SecTypeMIPS_ABIFlags SectionType = 0x7000002a // .MIPS.abiflags
	SecTypeProcHi        SectionType = 0x7fffffff // specific section header types
	SecTypeUserLo        SectionType = 0x80000000 // reserved range for application
	SecTypeUserHi        SectionType = 0xffffffff // specific indexes
)

// Section flags.
type sectionFlag uint32

const (
	secFlagWrite           sectionFlag = 0x1        // Section contains writable data
	secFlagAlloc           sectionFlag = 0x2        // Section occupies memory
	secFlagExecInstr       sectionFlag = 0x4        // Section contains instructions
	secFlagMerge           sectionFlag = 0x10       // Section may be merged
	secFlagStrings         sectionFlag = 0x20       // Section contains strings
	secFlagInfoLink        sectionFlag = 0x40       // sh_info holds section index
	secFlagLinkOrder       sectionFlag = 0x80       // Special ordering requirements
	secFlagOSNonConforming sectionFlag = 0x100      // OS-specific processing required
	secFlagGroup           sectionFlag = 0x200      // Member of section group
	secFlagTLS             sectionFlag = 0x400      // Section contains TLS data
	secFlagCompressed      sectionFlag = 0x800      // Section is compressed
	secFlagMaskOS          sectionFlag = 0x0ff00000 // OS-specific semantics
	secFlagMaskProc        sectionFlag = 0xf0000000 // Processor-specific semantics
)

// Section compression type.
type CompressionType int

const (
	CompressZLIB   CompressionType = 1          // ZLIB compression
	CompressZSTD   CompressionType = 2          // ZSTD compression
	CompressOSLo   CompressionType = 0x60000000 // First OS-specific
	CompressOSHi   CompressionType = 0x6fffffff // Last OS-specific
	CompressProcLo CompressionType = 0x70000000 // First processor-specific type
	CompressProcHi CompressionType = 0x7fffffff // Last processor-specific type
)

// Prog.Type
type ProgType uint32

const (
	ProgTypeNull    ProgType = 0 // Unused entry
	ProgTypeLoad    ProgType = 1 // Loadable segment
	ProgTypeDynamic ProgType = 2 // Dynamic linking information segment
	ProgTypeInterp  ProgType = 3 // Pathname of interpreter
	ProgTypeNote    ProgType = 4 // Auxiliary information
	ProgTypeSHLib   ProgType = 5 // Reserved (not used)
	ProgTypePHDR    ProgType = 6 // Location of program header itself
	ProgTypeTLS     ProgType = 7 // Thread local storage segment

	ProgTypeOSLo ProgType = 0x60000000 // First OS-specific

	ProgTypeGNU_EH_Frame ProgType = 0x6474e550 // Frame unwind information
	ProgTypeGNU_Stack    ProgType = 0x6474e551 // Stack flags
	ProgTypeGNU_RELRO    ProgType = 0x6474e552 // Read only after relocs
	ProgTypeGNU_Property ProgType = 0x6474e553 // GNU property
	ProgTypeGNU_MBIND_Lo ProgType = 0x6474e555 // Mbind segments start
	ProgTypeGNU_MBIND_Hi ProgType = 0x6474f554 // Mbind segments finish

	ProgTypePAXFlags ProgType = 0x65041580 // PAX flags

	ProgTypeOpenBSDRandomize ProgType = 0x65a3dbe6 // Random data
	ProgTypeOpenBSDWXNeeded  ProgType = 0x65a3dbe7 // W^X violations
	ProgTypeOpenBSDNoBTCFI   ProgType = 0x65a3dbe8 // No branch target CFI
	ProgTypeOpenBSDBootData  ProgType = 0x65a41be6 // Boot arguments

	ProgTypeSUNW_EH_Frame ProgType = 0x6474e550 // Frame unwind information
	ProgTypeSUNWStack     ProgType = 0x6ffffffb // Stack segment

	ProgTypeOSHi ProgType = 0x6fffffff // Last OS-specific

	ProgTypeProcLo ProgType = 0x70000000 // First processor-specific type

	ProgTypeARM_ARCHExt ProgType = 0x70000000 // Architecture compatibility
	ProgTypeARM_EXIdx   ProgType = 0x70000001 // Exception unwind tables

	ProgTypeAARCH64_ARCHExt ProgType = 0x70000000 // Architecture compatibility
	ProgTypeAARCH64_Unwind  ProgType = 0x70000001 // Exception unwind tables

	ProgTypeMIPS_REGInfo  ProgType = 0x70000000 // Register usage
	ProgTypeMIPS_RTProc   ProgType = 0x70000001 // Runtime procedures
	ProgTypeMIPS_Options  ProgType = 0x70000002 // Options
	ProgTypeMIPS_ABIFlags ProgType = 0x70000003 // ABI flags

	ProgTypeS390_PGSTE ProgType = 0x70000000 // 4k page table size

	ProgTypeProcHi ProgType = 0x7fffffff // Last processor-specific type
)

// Prog.Flag
type progFlag uint32

const (
	progFlagX        progFlag = 0x1        // Executable
	progFlagW        progFlag = 0x2        // Writable
	progFlagR        progFlag = 0x4        // Readable
	progFlagMASKOS   progFlag = 0x0ff00000 // Operating system-specific
	progFlagMASKPROC progFlag = 0xf0000000 // Processor-specific
)

type DynTag int

const (
	DT_NULL         DynTag = 0  // Terminating entry
	DT_NEEDED       DynTag = 1  // String table offset of a needed shared library
	DT_PLTRELSZ     DynTag = 2  // Total size in bytes of PLT relocations
	DT_PLTGOT       DynTag = 3  // Processor-dependent address
	DT_HASH         DynTag = 4  // Address of symbol hash table
	DT_STRTAB       DynTag = 5  // Address of string table
	DT_SYMTAB       DynTag = 6  // Address of symbol table
	DT_RELA         DynTag = 7  // Address of ElfNN_Rela relocations
	DT_RELASZ       DynTag = 8  // Total size of ElfNN_Rela relocations
	DT_RELAENT      DynTag = 9  // Size of each ElfNN_Rela relocation entry
	DT_STRSZ        DynTag = 10 // Size of string table
	DT_SYMENT       DynTag = 11 // Size of each symbol table entry
	DT_INIT         DynTag = 12 // Address of initialization function
	DT_FINI         DynTag = 13 // Address of finalization function
	DT_SONAME       DynTag = 14 // String table offset of shared object name
	DT_RPATH        DynTag = 15 // String table offset of library path. [sup]
	DT_SYMBOLIC     DynTag = 16 // Indicates "symbolic" linking. [sup]
	DT_REL          DynTag = 17 // Address of ElfNN_Rel relocations
	DT_RELSZ        DynTag = 18 // Total size of ElfNN_Rel relocations
	DT_RELENT       DynTag = 19 // Size of each ElfNN_Rel relocation
	DT_PLTREL       DynTag = 20 // Type of relocation used for PLT
	DT_DEBUG        DynTag = 21 // Reserved (not used)
	DT_TEXTREL      DynTag = 22 // Indicates there may be relocations in non-writable segments. [sup]
	DT_JMPREL       DynTag = 23 // Address of PLT relocations
	DT_BIND_NOW     DynTag = 24 // [sup]
	DT_INIT_ARRAY   DynTag = 25 // Address of the array of pointers to initialization functions
	DT_FINI_ARRAY   DynTag = 26 // Address of the array of pointers to termination functions
	DT_INIT_ARRAYSZ DynTag = 27 // Size in bytes of the array of initialization functions
	DT_FINI_ARRAYSZ DynTag = 28 // Size in bytes of the array of termination functions
	DT_RUNPATH      DynTag = 29 // String table offset of a null-terminated library search path string
	DT_FLAGS        DynTag = 30 // Object specific flag values
	DT_ENCODING     DynTag = 32 // Values greater than or equal to DT_ENCODING
	/*  and less than DT_LOOS follow the rules for
	the interpretation of the d_un union
	as follows: even == 'd_ptr', even == 'd_val'
	or none
	*/
	DT_PREINIT_ARRAY   DynTag = 32 // Address of the array of pointers to pre-initialization functions
	DT_PREINIT_ARRAYSZ DynTag = 33 // Size in bytes of the array of pre-initialization functions
	DT_SYMTAB_SHNDX    DynTag = 34 // Address of SHT_SYMTAB_SHNDX section

	DT_LOOS DynTag = 0x6000000d // First OS-specific
	DT_HIOS DynTag = 0x6ffff000 // Last OS-specific

	DT_VALRNGLO       DynTag = 0x6ffffd00
	DT_GNU_PRELINKED  DynTag = 0x6ffffdf5
	DT_GNU_CONFLICTSZ DynTag = 0x6ffffdf6
	DT_GNU_LIBLISTSZ  DynTag = 0x6ffffdf7
	DT_CHECKSUM       DynTag = 0x6ffffdf8
	DT_PLTPADSZ       DynTag = 0x6ffffdf9
	DT_MOVEENT        DynTag = 0x6ffffdfa
	DT_MOVESZ         DynTag = 0x6ffffdfb
	DT_FEATURE        DynTag = 0x6ffffdfc
	DT_POSFLAG_1      DynTag = 0x6ffffdfd
	DT_SYMINSZ        DynTag = 0x6ffffdfe
	DT_SYMINENT       DynTag = 0x6ffffdff
	DT_VALRNGHI       DynTag = 0x6ffffdff

	DT_ADDRRNGLO    DynTag = 0x6ffffe00
	DT_GNU_HASH     DynTag = 0x6ffffef5
	DT_TLSDESC_PLT  DynTag = 0x6ffffef6
	DT_TLSDESC_GOT  DynTag = 0x6ffffef7
	DT_GNU_CONFLICT DynTag = 0x6ffffef8
	DT_GNU_LIBLIST  DynTag = 0x6ffffef9
	DT_CONFIG       DynTag = 0x6ffffefa
	DT_DEPAUDIT     DynTag = 0x6ffffefb
	DT_AUDIT        DynTag = 0x6ffffefc
	DT_PLTPAD       DynTag = 0x6ffffefd
	DT_MOVETAB      DynTag = 0x6ffffefe
	DT_SYMINFO      DynTag = 0x6ffffeff
	DT_ADDRRNGHI    DynTag = 0x6ffffeff

	DT_VERSYM     DynTag = 0x6ffffff0
	DT_RELACOUNT  DynTag = 0x6ffffff9
	DT_RELCOUNT   DynTag = 0x6ffffffa
	DT_FLAGS_1    DynTag = 0x6ffffffb
	DT_VERDEF     DynTag = 0x6ffffffc
	DT_VERDEFNUM  DynTag = 0x6ffffffd
	DT_VERNEED    DynTag = 0x6ffffffe
	DT_VERNEEDNUM DynTag = 0x6fffffff

	DT_LOPROC DynTag = 0x70000000 // First processor-specific type

	DT_MIPS_RLD_VERSION           DynTag = 0x70000001
	DT_MIPS_TIME_STAMP            DynTag = 0x70000002
	DT_MIPS_ICHECKSUM             DynTag = 0x70000003
	DT_MIPS_IVERSION              DynTag = 0x70000004
	DT_MIPS_FLAGS                 DynTag = 0x70000005
	DT_MIPS_BASE_ADDRESS          DynTag = 0x70000006
	DT_MIPS_MSYM                  DynTag = 0x70000007
	DT_MIPS_CONFLICT              DynTag = 0x70000008
	DT_MIPS_LIBLIST               DynTag = 0x70000009
	DT_MIPS_LOCAL_GOTNO           DynTag = 0x7000000a
	DT_MIPS_CONFLICTNO            DynTag = 0x7000000b
	DT_MIPS_LIBLISTNO             DynTag = 0x70000010
	DT_MIPS_SYMTABNO              DynTag = 0x70000011
	DT_MIPS_UNREFEXTNO            DynTag = 0x70000012
	DT_MIPS_GOTSYM                DynTag = 0x70000013
	DT_MIPS_HIPAGENO              DynTag = 0x70000014
	DT_MIPS_RLD_MAP               DynTag = 0x70000016
	DT_MIPS_DELTA_CLASS           DynTag = 0x70000017
	DT_MIPS_DELTA_CLASS_NO        DynTag = 0x70000018
	DT_MIPS_DELTA_INSTANCE        DynTag = 0x70000019
	DT_MIPS_DELTA_INSTANCE_NO     DynTag = 0x7000001a
	DT_MIPS_DELTA_RELOC           DynTag = 0x7000001b
	DT_MIPS_DELTA_RELOC_NO        DynTag = 0x7000001c
	DT_MIPS_DELTA_SYM             DynTag = 0x7000001d
	DT_MIPS_DELTA_SYM_NO          DynTag = 0x7000001e
	DT_MIPS_DELTA_CLASSSYM        DynTag = 0x70000020
	DT_MIPS_DELTA_CLASSSYM_NO     DynTag = 0x70000021
	DT_MIPS_CXX_FLAGS             DynTag = 0x70000022
	DT_MIPS_PIXIE_INIT            DynTag = 0x70000023
	DT_MIPS_SYMBOL_LIB            DynTag = 0x70000024
	DT_MIPS_LOCALPAGE_GOTIDX      DynTag = 0x70000025
	DT_MIPS_LOCAL_GOTIDX          DynTag = 0x70000026
	DT_MIPS_HIDDEN_GOTIDX         DynTag = 0x70000027
	DT_MIPS_PROTECTED_GOTIDX      DynTag = 0x70000028
	DT_MIPS_OPTIONS               DynTag = 0x70000029
	DT_MIPS_INTERFACE             DynTag = 0x7000002a
	DT_MIPS_DYNSTR_ALIGN          DynTag = 0x7000002b
	DT_MIPS_INTERFACE_SIZE        DynTag = 0x7000002c
	DT_MIPS_RLD_TEXT_RESOLVE_ADDR DynTag = 0x7000002d
	DT_MIPS_PERF_SUFFIX           DynTag = 0x7000002e
	DT_MIPS_COMPACT_SIZE          DynTag = 0x7000002f
	DT_MIPS_GP_VALUE              DynTag = 0x70000030
	DT_MIPS_AUX_DYNAMIC           DynTag = 0x70000031
	DT_MIPS_PLTGOT                DynTag = 0x70000032
	DT_MIPS_RWPLT                 DynTag = 0x70000034
	DT_MIPS_RLD_MAP_REL           DynTag = 0x70000035

	DT_PPC_GOT DynTag = 0x70000000
	DT_PPC_OPT DynTag = 0x70000001

	DT_PPC64_GLINK DynTag = 0x70000000
	DT_PPC64_OPD   DynTag = 0x70000001
	DT_PPC64_OPDSZ DynTag = 0x70000002
	DT_PPC64_OPT   DynTag = 0x70000003

	DT_SPARC_REGISTER DynTag = 0x70000001

	DT_AUXILIARY DynTag = 0x7ffffffd
	DT_USED      DynTag = 0x7ffffffe
	DT_FILTER    DynTag = 0x7fffffff

	DT_HIPROC DynTag = 0x7fffffff // Last processor-specific type
)

// DT_FLAGS values.
type dynFlag int

const (
	DF_ORIGIN     dynFlag = 0x0001 // Indicates that the object being loaded may make reference to the $ORIGIN substitution string
	DF_SYMBOLIC   dynFlag = 0x0002 // Indicates "symbolic" linking
	DF_TEXTREL    dynFlag = 0x0004 // Indicates there may be relocations in non-writable segments
	DF_BIND_NOW   dynFlag = 0x0008 // Indicates that the dynamic linker should process all relocations for the object containing this entry before transferring control to the program
	DF_STATIC_TLS dynFlag = 0x0010 // Indicates that the shared object or executable contains code using a static thread-local storage scheme
)

// DT_FLAGS_1 values.
type dynFlag1 uint32

const (
	// Indicates that all relocations for this object must be processed before
	// returning control to the program.
	DF_1_NOW dynFlag1 = 0x00000001
	// Unused.
	DF_1_GLOBAL dynFlag1 = 0x00000002
	// Indicates that the object is a member of a group.
	DF_1_GROUP dynFlag1 = 0x00000004
	// Indicates that the object cannot be deleted from a process.
	DF_1_NODELETE dynFlag1 = 0x00000008
	// Meaningful only for filters. Indicates that all associated filtees be
	// processed immediately.
	DF_1_LOADFLTR dynFlag1 = 0x00000010
	// Indicates that this object's initialization section be run before any other
	// objects loaded.
	DF_1_INITFIRST dynFlag1 = 0x00000020
	// Indicates that the object cannot be added to a running process with dlopen.
	DF_1_NOOPEN dynFlag1 = 0x00000040
	// Indicates the object requires $ORIGIN processing.
	DF_1_ORIGIN dynFlag1 = 0x00000080
	// Indicates that the object should use direct binding information.
	DF_1_DIRECT dynFlag1 = 0x00000100
	// Unused.
	DF_1_TRANS dynFlag1 = 0x00000200
	// Indicates that the objects symbol table is to interpose before all symbols
	// except the primary load object, which is typically the executable.
	DF_1_INTERPOSE dynFlag1 = 0x00000400
	// Indicates that the search for dependencies of this object ignores any
	// default library search paths.
	DF_1_NODEFLIB dynFlag1 = 0x00000800
	// Indicates that this object is not dumped by dldump. Candidates are objects
	// with no relocations that might get included when generating alternative
	// objects using.
	DF_1_NODUMP dynFlag1 = 0x00001000
	// Identifies this object as a configuration alternative object generated by
	// crle. Triggers the runtime linker to search for a configuration file $ORIGIN/ld.config.app-name.
	DF_1_CONFALT dynFlag1 = 0x00002000
	// Meaningful only for filtees. Terminates a filters search for any
	// further filtees.
	DF_1_ENDFILTEE dynFlag1 = 0x00004000
	// Indicates that this object has displacement relocations applied.
	DF_1_DISPRELDNE dynFlag1 = 0x00008000
	// Indicates that this object has displacement relocations pending.
	DF_1_DISPRELPND dynFlag1 = 0x00010000
	// Indicates that this object contains symbols that cannot be directly
	// bound to.
	DF_1_NODIRECT dynFlag1 = 0x00020000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_IGNMULDEF dynFlag1 = 0x00040000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NOKSYMS dynFlag1 = 0x00080000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NOHDR dynFlag1 = 0x00100000
	// Indicates that this object has been edited or has been modified since the
	// objects original construction by the link-editor.
	DF_1_EDITED dynFlag1 = 0x00200000
	// Reserved for internal use by the kernel runtime-linker.
	DF_1_NORELOC dynFlag1 = 0x00400000
	// Indicates that the object contains individual symbols that should interpose
	// before all symbols except the primary load object, which is typically the
	// executable.
	DF_1_SYMINTPOSE dynFlag1 = 0x00800000
	// Indicates that the executable requires global auditing.
	DF_1_GLOBAUDIT dynFlag1 = 0x01000000
	// Indicates that the object defines, or makes reference to singleton symbols.
	DF_1_SINGLETON dynFlag1 = 0x02000000
	// Indicates that the object is a stub.
	DF_1_STUB dynFlag1 = 0x04000000
	// Indicates that the object is a position-independent executable.
	DF_1_PIE dynFlag1 = 0x08000000
	// Indicates that the object is a kernel module.
	DF_1_KMOD dynFlag1 = 0x10000000
	// Indicates that the object is a weak standard filter.
	DF_1_WEAKFILTER dynFlag1 = 0x20000000
	// Unused.
	DF_1_NOCOMMON dynFlag1 = 0x40000000
)

// NType values; used in core files.
type NType int

const (
	NTypeProcStatus NType = 1 // Process status
	NTypeFPRegSet   NType = 2 // Floating point registers
	NTypeProcPSInfo NType = 3 // Process state info
)

// Symbol Binding - ELFNN_ST_BIND - st_info
type SymBind int

const (
	SymBindLocal  SymBind = 0  // Local symbol
	SymBindGlobal SymBind = 1  // Global symbol
	SymBindWeak   SymBind = 2  // like global - lower precedence
	SymBindOSLo   SymBind = 10 // Reserved range for operating system
	SymBindOSHi   SymBind = 12 // specific semantics
	SymBindProcLo SymBind = 13 // reserved range for processor
	SymBindProcHi SymBind = 15 // specific semantics
)

/* Symbol type - ELFNN_ST_TYPE - st_info */
type SymType int

const (
	SymTypeNoType  SymType = 0  // Unspecified type
	SymTypeObject  SymType = 1  // Data object
	SymTypeFunc    SymType = 2  // Function
	SymTypeSection SymType = 3  // Section
	SymTypeFile    SymType = 4  // Source file
	SymTypeCommon  SymType = 5  // Uninitialized common block
	SymTypeTLS     SymType = 6  // TLS object
	SymTypeOSLo    SymType = 10 // rsv:OSLo
	SymTypeOSHi    SymType = 12 // rsv:OSHi
	SymTypeProcLo  SymType = 13 // rsv:ProcLo
	SymTypeProcHi  SymType = 15 // rsv:ProcHi

	// Non-standard symbol types
	SymTypeRelc      SymType = 8  // Complex relocation expression
	SymTypeSRelc     SymType = 9  // Signed complex relocation expression
	SymTypeGNU_IFunc SymType = 10 // Indirect code object
)

// Symbol visibility - ELFNN_ST_VISIBILITY - st_other
type SymVis int

const (
	SymVisDefault   SymVis = 0x0 // Default visibility (see binding)
	SymVisInternal  SymVis = 0x1 // Internal: Special meaning in relocatable objects
	SymVisHidden    SymVis = 0x2 // Hidden: Not visible
	SymVisProtected SymVis = 0x3 // Protected: visible but not preemptible
)

// Relocation types for x86-64.
type RX86_64 int

const (
	Rx86_64None            RX86_64 = 0  // No relocation
	Rx86_6464              RX86_64 = 1  // Add 64 bit symbol value
	Rx86_64PC32            RX86_64 = 2  // PC-relative 32 bit signed sym value
	Rx86_64GOT32           RX86_64 = 3  // PC-relative 32 bit GOT offset
	Rx86_64PLT32           RX86_64 = 4  // PC-relative 32 bit PLT offset
	Rx86_64Copy            RX86_64 = 5  // Copy data from shared object
	Rx86_64GLOB_Data       RX86_64 = 6  // Set GOT entry to data address
	Rx86_64JMP_Slot        RX86_64 = 7  // Set GOT entry to code address
	Rx86_64RELATIVE        RX86_64 = 8  // Add load address of shared object
	Rx86_64GOTPCREL        RX86_64 = 9  // Add 32 bit signed pcrel offset to GOT
	Rx86_6432              RX86_64 = 10 // Add 32 bit zero extended symbol value
	Rx86_6432S             RX86_64 = 11 // Add 32 bit sign extended symbol value
	Rx86_6416              RX86_64 = 12 // Add 16 bit zero extended symbol value
	Rx86_64PC16            RX86_64 = 13 // Add 16 bit signed extended pc relative symbol value
	Rx86_648               RX86_64 = 14 // Add 8 bit zero extended symbol value
	Rx86_64PC8             RX86_64 = 15 // Add 8 bit signed extended pc relative symbol value
	Rx86_64DTPMOD64        RX86_64 = 16 // ID of module containing symbol
	Rx86_64DTPOFF64        RX86_64 = 17 // Offset in TLS block
	Rx86_64TPOFF64         RX86_64 = 18 // Offset in static TLS block
	Rx86_64TLSGD           RX86_64 = 19 // PC relative offset to GD GOT entry
	Rx86_64TLSLD           RX86_64 = 20 // PC relative offset to LD GOT entry
	Rx86_64DTPOFF32        RX86_64 = 21 // Offset in TLS block
	Rx86_64GOTTPOFF        RX86_64 = 22 // PC relative offset to IE GOT entry
	Rx86_64TPOFF32         RX86_64 = 23 // Offset in static TLS block
	Rx86_64PC64            RX86_64 = 24 // PC relative 64-bit sign extended symbol value
	Rx86_64GOTOFF64        RX86_64 = 25 // GOTOFF64
	Rx86_64GOTPC32         RX86_64 = 26 // GOTPC32
	Rx86_64GOT64           RX86_64 = 27 // GOT64
	Rx86_64GOTPCREL64      RX86_64 = 28 // GOTPCREL64
	Rx86_64GOTPC64         RX86_64 = 29 // GOTPC64
	Rx86_64GOTPLT64        RX86_64 = 30 // GOTPLT64
	Rx86_64PLTOFF64        RX86_64 = 31 // PLTOFF64
	Rx86_64SIZE32          RX86_64 = 32 // SIZE32
	Rx86_64SIZE64          RX86_64 = 33 // SIZE64
	Rx86_64GOTPC32_TLSDESC RX86_64 = 34 // GOTPC32_TLSDESC
	Rx86_64TLSDESC_CALL    RX86_64 = 35 // TLSDESC_CALL
	Rx86_64TLSDESC         RX86_64 = 36 // TLSDESC
	Rx86_64IRELATIVE       RX86_64 = 37 // IRELATIVE
	Rx86_64RELATIVE64      RX86_64 = 38 // RELATIVE64
	Rx86_64PC32_BND        RX86_64 = 39 // PC32_BND
	Rx86_64PLT32_BND       RX86_64 = 40 // PLT32_BND
	Rx86_64GOTPCRELX       RX86_64 = 41 // GOTPCRELX
	Rx86_64REX_GOTPCRELX   RX86_64 = 42 // REX_GOTPCRELX
)

// Relocation types for AArch64 (aka arm64)
type RAARCH64 int

const (
	RAArch64None                            RAARCH64 = 0    // None
	RAArch64P32_ABS32                       RAARCH64 = 1    // P32_ABS32
	RAArch64P32_ABS16                       RAARCH64 = 2    // P32_ABS16
	RAArch64P32_PREL32                      RAARCH64 = 3    // P32_PREL32
	RAArch64P32_PREL16                      RAARCH64 = 4    // P32_PREL16
	RAArch64P32_MOVW_UABS_G0                RAARCH64 = 5    // P32_MOVW_UABS_G0
	RAArch64P32_MOVW_UABS_G0_NC             RAARCH64 = 6    // P32_MOVW_UABS_G0_NC
	RAArch64P32_MOVW_UABS_G1                RAARCH64 = 7    // P32_MOVW_UABS_G1
	RAArch64P32_MOVW_SABS_G0                RAARCH64 = 8    // P32_MOVW_SABS_G0
	RAArch64P32_LD_PREL_LO19                RAARCH64 = 9    // P32_LD_PREL_LO19
	RAArch64P32_ADR_PREL_LO21               RAARCH64 = 10   // P32_ADR_PREL_LO21
	RAArch64P32_ADR_PREL_PG_HI21            RAARCH64 = 11   // P32_ADR_PREL_PG_HI21
	RAArch64P32_ADD_ABS_LO12_NC             RAARCH64 = 12   // P32_ADD_ABS_LO12_NC
	RAArch64P32_LDST8_ABS_LO12_NC           RAARCH64 = 13   // P32_LDST8_ABS_LO12_NC
	RAArch64P32_LDST16_ABS_LO12_NC          RAARCH64 = 14   // P32_LDST16_ABS_LO12_NC
	RAArch64P32_LDST32_ABS_LO12_NC          RAARCH64 = 15   // P32_LDST32_ABS_LO12_NC
	RAArch64P32_LDST64_ABS_LO12_NC          RAARCH64 = 16   // P32_LDST64_ABS_LO12_NC
	RAArch64P32_LDST128_ABS_LO12_NC         RAARCH64 = 17   // P32_LDST128_ABS_LO12_NC
	RAArch64P32_TSTBR14                     RAARCH64 = 18   // P32_TSTBR14
	RAArch64P32_CONDBR19                    RAARCH64 = 19   // P32_CONDBR19
	RAArch64P32_JUMP26                      RAARCH64 = 20   // P32_JUMP26
	RAArch64P32_CALL26                      RAARCH64 = 21   // P32_CALL26
	RAArch64P32_GOT_LD_PREL19               RAARCH64 = 25   // P32_GOT_LD_PREL19
	RAArch64P32_ADR_GOT_PAGE                RAARCH64 = 26   // P32_ADR_GOT_PAGE
	RAArch64P32_LD32_GOT_LO12_NC            RAARCH64 = 27   // P32_LD32_GOT_LO12_NC
	RAArch64P32_TLSGD_ADR_PAGE21            RAARCH64 = 81   // P32_TLSGD_ADR_PAGE21
	RAArch64P32_TLSGD_ADD_LO12_NC           RAARCH64 = 82   // P32_TLSGD_ADD_LO12_NC
	RAArch64P32_TLSIE_ADR_GOTTPREL_PAGE21   RAARCH64 = 103  // P32_TLSIE_ADR_GOTTPREL_PAGE21
	RAArch64P32_TLSIE_LD32_GOTTPREL_LO12_NC RAARCH64 = 104  // P32_TLSIE_LD32_GOTTPREL_LO12_NC
	RAArch64P32_TLSIE_LD_GOTTPREL_PREL19    RAARCH64 = 105  // P32_TLSIE_LD_GOTTPREL_PREL19
	RAArch64P32_TLSLE_MOVW_TPREL_G1         RAARCH64 = 106  // P32_TLSLE_MOVW_TPREL_G1
	RAArch64P32_TLSLE_MOVW_TPREL_G0         RAARCH64 = 107  // P32_TLSLE_MOVW_TPREL_G0
	RAArch64P32_TLSLE_MOVW_TPREL_G0_NC      RAARCH64 = 108  // P32_TLSLE_MOVW_TPREL_G0_NC
	RAArch64P32_TLSLE_ADD_TPREL_HI12        RAARCH64 = 109  // P32_TLSLE_ADD_TPREL_HI12
	RAArch64P32_TLSLE_ADD_TPREL_LO12        RAARCH64 = 110  // P32_TLSLE_ADD_TPREL_LO12
	RAArch64P32_TLSLE_ADD_TPREL_LO12_NC     RAARCH64 = 111  // P32_TLSLE_ADD_TPREL_LO12_NC
	RAArch64P32_TLSDESC_LD_PREL19           RAARCH64 = 122  // P32_TLSDESC_LD_PREL19
	RAArch64P32_TLSDESC_ADR_PREL21          RAARCH64 = 123  // P32_TLSDESC_ADR_PREL21
	RAArch64P32_TLSDESC_ADR_PAGE21          RAARCH64 = 124  // P32_TLSDESC_ADR_PAGE21
	RAArch64P32_TLSDESC_LD32_LO12_NC        RAARCH64 = 125  // P32_TLSDESC_LD32_LO12_NC
	RAArch64P32_TLSDESC_ADD_LO12_NC         RAARCH64 = 126  // P32_TLSDESC_ADD_LO12_NC
	RAArch64P32_TLSDESC_CALL                RAARCH64 = 127  // P32_TLSDESC_CALL
	RAArch64P32_COPY                        RAARCH64 = 180  // P32_COPY
	RAArch64P32_GLOB_DAT                    RAARCH64 = 181  // P32_GLOB_DAT
	RAArch64P32_JUMP_SLOT                   RAARCH64 = 182  // P32_JUMP_SLOT
	RAArch64P32_RELATIVE                    RAARCH64 = 183  // P32_RELATIVE
	RAArch64P32_TLS_DTPMOD                  RAARCH64 = 184  // P32_TLS_DTPMOD
	RAArch64P32_TLS_DTPREL                  RAARCH64 = 185  // P32_TLS_DTPREL
	RAArch64P32_TLS_TPREL                   RAARCH64 = 186  // P32_TLS_TPREL
	RAArch64P32_TLSDESC                     RAARCH64 = 187  // P32_TLSDESC
	RAArch64P32_IRELATIVE                   RAARCH64 = 188  // P32_IRELATIVE
	RAArch64NULL                            RAARCH64 = 256  // NULL
	RAArch64ABS64                           RAARCH64 = 257  // ABS64
	RAArch64ABS32                           RAARCH64 = 258  // ABS32
	RAArch64ABS16                           RAARCH64 = 259  // ABS16
	RAArch64PREL64                          RAARCH64 = 260  // PREL64
	RAArch64PREL32                          RAARCH64 = 261  // PREL32
	RAArch64PREL16                          RAARCH64 = 262  // PREL16
	RAArch64MOVW_UABS_G0                    RAARCH64 = 263  // MOVW_UABS_G0
	RAArch64MOVW_UABS_G0_NC                 RAARCH64 = 264  // MOVW_UABS_G0_NC
	RAArch64MOVW_UABS_G1                    RAARCH64 = 265  // MOVW_UABS_G1
	RAArch64MOVW_UABS_G1_NC                 RAARCH64 = 266  // MOVW_UABS_G1_NC
	RAArch64MOVW_UABS_G2                    RAARCH64 = 267  // MOVW_UABS_G2
	RAArch64MOVW_UABS_G2_NC                 RAARCH64 = 268  // MOVW_UABS_G2_NC
	RAArch64MOVW_UABS_G3                    RAARCH64 = 269  // MOVW_UABS_G3
	RAArch64MOVW_SABS_G0                    RAARCH64 = 270  // MOVW_SABS_G0
	RAArch64MOVW_SABS_G1                    RAARCH64 = 271  // MOVW_SABS_G1
	RAArch64MOVW_SABS_G2                    RAARCH64 = 272  // MOVW_SABS_G2
	RAArch64LD_PREL_LO19                    RAARCH64 = 273  // LD_PREL_LO19
	RAArch64ADR_PREL_LO21                   RAARCH64 = 274  // ADR_PREL_LO21
	RAArch64ADR_PREL_PG_HI21                RAARCH64 = 275  // ADR_PREL_PG_HI21
	RAArch64ADR_PREL_PG_HI21_NC             RAARCH64 = 276  // ADR_PREL_PG_HI21_NC
	RAArch64ADD_ABS_LO12_NC                 RAARCH64 = 277  // ADD_ABS_LO12_NC
	RAArch64LDST8_ABS_LO12_NC               RAARCH64 = 278  // LDST8_ABS_LO12_NC
	RAArch64TSTBR14                         RAARCH64 = 279  // TSTBR14
	RAArch64CONDBR19                        RAARCH64 = 280  // CONDBR19
	RAArch64JUMP26                          RAARCH64 = 282  // JUMP26
	RAArch64CALL26                          RAARCH64 = 283  // CALL26
	RAArch64LDST16_ABS_LO12_NC              RAARCH64 = 284  // LDST16_ABS_LO12_NC
	RAArch64LDST32_ABS_LO12_NC              RAARCH64 = 285  // LDST32_ABS_LO12_NC
	RAArch64LDST64_ABS_LO12_NC              RAARCH64 = 286  // LDST64_ABS_LO12_NC
	RAArch64LDST128_ABS_LO12_NC             RAARCH64 = 299  // LDST128_ABS_LO12_NC
	RAArch64GOT_LD_PREL19                   RAARCH64 = 309  // GOT_LD_PREL19
	RAArch64LD64_GOTOFF_LO15                RAARCH64 = 310  // LD64_GOTOFF_LO15
	RAArch64ADR_GOT_PAGE                    RAARCH64 = 311  // ADR_GOT_PAGE
	RAArch64LD64_GOT_LO12_NC                RAARCH64 = 312  // LD64_GOT_LO12_NC
	RAArch64LD64_GOTPAGE_LO15               RAARCH64 = 313  // LD64_GOTPAGE_LO15
	RAArch64TLSGD_ADR_PREL21                RAARCH64 = 512  // TLSGD_ADR_PREL21
	RAArch64TLSGD_ADR_PAGE21                RAARCH64 = 513  // TLSGD_ADR_PAGE21
	RAArch64TLSGD_ADD_LO12_NC               RAARCH64 = 514  // TLSGD_ADD_LO12_NC
	RAArch64TLSGD_MOVW_G1                   RAARCH64 = 515  // TLSGD_MOVW_G1
	RAArch64TLSGD_MOVW_G0_NC                RAARCH64 = 516  // TLSGD_MOVW_G0_NC
	RAArch64TLSLD_ADR_PREL21                RAARCH64 = 517  // TLSLD_ADR_PREL21
	RAArch64TLSLD_ADR_PAGE21                RAARCH64 = 518  // TLSLD_ADR_PAGE21
	RAArch64TLSIE_MOVW_GOTTPREL_G1          RAARCH64 = 539  // TLSIE_MOVW_GOTTPREL_G1
	RAArch64TLSIE_MOVW_GOTTPREL_G0_NC       RAARCH64 = 540  // TLSIE_MOVW_GOTTPREL_G0_NC
	RAArch64TLSIE_ADR_GOTTPREL_PAGE21       RAARCH64 = 541  // TLSIE_ADR_GOTTPREL_PAGE21
	RAArch64TLSIE_LD64_GOTTPREL_LO12_NC     RAARCH64 = 542  // TLSIE_LD64_GOTTPREL_LO12_NC
	RAArch64TLSIE_LD_GOTTPREL_PREL19        RAARCH64 = 543  // TLSIE_LD_GOTTPREL_PREL19
	RAArch64TLSLE_MOVW_TPREL_G2             RAARCH64 = 544  // TLSLE_MOVW_TPREL_G2
	RAArch64TLSLE_MOVW_TPREL_G1             RAARCH64 = 545  // TLSLE_MOVW_TPREL_G1
	RAArch64TLSLE_MOVW_TPREL_G1_NC          RAARCH64 = 546  // TLSLE_MOVW_TPREL_G1_NC
	RAArch64TLSLE_MOVW_TPREL_G0             RAARCH64 = 547  // TLSLE_MOVW_TPREL_G0
	RAArch64TLSLE_MOVW_TPREL_G0_NC          RAARCH64 = 548  // TLSLE_MOVW_TPREL_G0_NC
	RAArch64TLSLE_ADD_TPREL_HI12            RAARCH64 = 549  // TLSLE_ADD_TPREL_HI12
	RAArch64TLSLE_ADD_TPREL_LO12            RAARCH64 = 550  // TLSLE_ADD_TPREL_LO12
	RAArch64TLSLE_ADD_TPREL_LO12_NC         RAARCH64 = 551  // TLSLE_ADD_TPREL_LO12_NC
	RAArch64TLSDESC_LD_PREL19               RAARCH64 = 560  // TLSDESC_LD_PREL19
	RAArch64TLSDESC_ADR_PREL21              RAARCH64 = 561  // TLSDESC_ADR_PREL21
	RAArch64TLSDESC_ADR_PAGE21              RAARCH64 = 562  // TLSDESC_ADR_PAGE21
	RAArch64TLSDESC_LD64_LO12_NC            RAARCH64 = 563  // TLSDESC_LD64_LO12_NC
	RAArch64TLSDESC_ADD_LO12_NC             RAARCH64 = 564  // TLSDESC_ADD_LO12_NC
	RAArch64TLSDESC_OFF_G1                  RAARCH64 = 565  // TLSDESC_OFF_G1
	RAArch64TLSDESC_OFF_G0_NC               RAARCH64 = 566  // TLSDESC_OFF_G0_NC
	RAArch64TLSDESC_LDR                     RAARCH64 = 567  // TLSDESC_LDR
	RAArch64TLSDESC_ADD                     RAARCH64 = 568  // TLSDESC_ADD
	RAArch64TLSDESC_CALL                    RAARCH64 = 569  // TLSDESC_CALL
	RAArch64TLSLE_LDST128_TPREL_LO12        RAARCH64 = 570  // TLSLE_LDST128_TPREL_LO12
	RAArch64TLSLE_LDST128_TPREL_LO12_NC     RAARCH64 = 571  // TLSLE_LDST128_TPREL_LO12_NC
	RAArch64TLSLD_LDST128_DTPREL_LO12       RAARCH64 = 572  // TLSLD_LDST128_DTPREL_LO12
	RAArch64TLSLD_LDST128_DTPREL_LO12_NC    RAARCH64 = 573  // TLSLD_LDST128_DTPREL_LO12_NC
	RAArch64COPY                            RAARCH64 = 1024 // COPY
	RAArch64GLOB_DAT                        RAARCH64 = 1025 // GLOB_DAT
	RAArch64JUMP_SLOT                       RAARCH64 = 1026 // JUMP_SLOT
	RAArch64RELATIVE                        RAARCH64 = 1027 // RELATIVE
	RAArch64TLS_DTPMOD64                    RAARCH64 = 1028 // TLS_DTPMOD64
	RAArch64TLS_DTPREL64                    RAARCH64 = 1029 // TLS_DTPREL64
	RAArch64TLS_TPREL64                     RAARCH64 = 1030 // TLS_TPREL64
	RAArch64TLSDESC                         RAARCH64 = 1031 // TLSDESC
	RAArch64IRELATIVE                       RAARCH64 = 1032 // IRELATIVE
)

// Relocation types for ARM.
type RARM int

const (
	RARMNone               RARM = 0   // No relocation
	RARMPC24               RARM = 1   // PC24
	RARMABS32              RARM = 2   // ABS32
	RARMREL32              RARM = 3   // REL32
	RARMPC13               RARM = 4   // PC13
	RARMABS16              RARM = 5   // ABS16
	RARMABS12              RARM = 6   // ABS12
	RARMTHM_ABS5           RARM = 7   // THM_ABS5
	RARMABS8               RARM = 8   // ABS8
	RARMSBREL32            RARM = 9   // SBREL32
	RARMTHM_PC22           RARM = 10  // THM_PC22
	RARMTHM_PC8            RARM = 11  // THM_PC8
	RARMAMP_VCALL9         RARM = 12  // AMP_VCALL9
	RARMSWI24              RARM = 13  // SWI24
	RARMTHM_SWI8           RARM = 14  // THM_SWI8
	RARMXPC25              RARM = 15  // XPC25
	RARMTHM_XPC22          RARM = 16  // THM_XPC22
	RARMTLS_DTPMOD32       RARM = 17  // TLS_DTPMOD32
	RARMTLS_DTPOFF32       RARM = 18  // TLS_DTPOFF32
	RARMTLS_TPOFF32        RARM = 19  // TLS_TPOFF32
	RARMCOPY               RARM = 20  // Copy data from shared object
	RARMGLOB_DAT           RARM = 21  // Set GOT entry to data address
	RARMJUMP_SLOT          RARM = 22  // Set GOT entry to code address
	RARMRELATIVE           RARM = 23  // Add load address of shared object
	RARMGOTOFF             RARM = 24  // Add GOT-relative symbol address
	RARMGOTPC              RARM = 25  // Add PC-relative GOT table address
	RARMGOT32              RARM = 26  // Add PC-relative GOT offset
	RARMPLT32              RARM = 27  // Add PC-relative PLT offset
	RARMCALL               RARM = 28  // CALL
	RARMJUMP24             RARM = 29  // JUMP24
	RARMTHM_JUMP24         RARM = 30  // THM_JUMP24
	RARMBASE_ABS           RARM = 31  // BASE_ABS
	RARMALU_PCREL_7_0      RARM = 32  // ALU_PCREL_7_0
	RARMALU_PCREL_15_8     RARM = 33  // ALU_PCREL_15_8
	RARMALU_PCREL_23_15    RARM = 34  // ALU_PCREL_23_15
	RARMLDR_SBREL_11_10_NC RARM = 35  // LDR_SBREL_11_10_NC
	RARMALU_SBREL_19_12_NC RARM = 36  // ALU_SBREL_19_12_NC
	RARMALU_SBREL_27_20_CK RARM = 37  // ALU_SBREL_27_20_CK
	RARMTARGET1            RARM = 38  // TARGET1
	RARMSBREL31            RARM = 39  // SBREL31
	RARMV4BX               RARM = 40  // V4BX
	RARMTARGET2            RARM = 41  // TARGET2
	RARMPREL31             RARM = 42  // PREL31
	RARMMOVW_ABS_NC        RARM = 43  // MOVW_ABS_NC
	RARMMOVT_ABS           RARM = 44  // MOVT_ABS
	RARMMOVW_PREL_NC       RARM = 45  // MOVW_PREL_NC
	RARMMOVT_PREL          RARM = 46  // MOVT_PREL
	RARMTHM_MOVW_ABS_NC    RARM = 47  // THM_MOVW_ABS_NC
	RARMTHM_MOVT_ABS       RARM = 48  // THM_MOVT_ABS
	RARMTHM_MOVW_PREL_NC   RARM = 49  // THM_MOVW_PREL_NC
	RARMTHM_MOVT_PREL      RARM = 50  // THM_MOVT_PREL
	RARMTHM_JUMP19         RARM = 51  // THM_JUMP19
	RARMTHM_JUMP6          RARM = 52  // THM_JUMP6
	RARMTHM_ALU_PREL_11_0  RARM = 53  // THM_ALU_PREL_11_0
	RARMTHM_PC12           RARM = 54  // THM_PC12
	RARMABS32_NOI          RARM = 55  // ABS32_NOI
	RARMREL32_NOI          RARM = 56  // REL32_NOI
	RARMALU_PC_G0_NC       RARM = 57  // ALU_PC_G0_NC
	RARMALU_PC_G0          RARM = 58  // ALU_PC_G0
	RARMALU_PC_G1_NC       RARM = 59  // ALU_PC_G1_NC
	RARMALU_PC_G1          RARM = 60  // ALU_PC_G1
	RARMALU_PC_G2          RARM = 61  // ALU_PC_G2
	RARMLDR_PC_G1          RARM = 62  // LDR_PC_G1
	RARMLDR_PC_G2          RARM = 63  // LDR_PC_G2
	RARMLDRS_PC_G0         RARM = 64  // LDRS_PC_G0
	RARMLDRS_PC_G1         RARM = 65  // LDRS_PC_G1
	RARMLDRS_PC_G2         RARM = 66  // LDRS_PC_G2
	RARMLDC_PC_G0          RARM = 67  // LDC_PC_G0
	RARMLDC_PC_G1          RARM = 68  // LDC_PC_G1
	RARMLDC_PC_G2          RARM = 69  // LDC_PC_G2
	RARMALU_SB_G0_NC       RARM = 70  // ALU_SB_G0_NC
	RARMALU_SB_G0          RARM = 71  // ALU_SB_G0
	RARMALU_SB_G1_NC       RARM = 72  // ALU_SB_G1_NC
	RARMALU_SB_G1          RARM = 73  // ALU_SB_G1
	RARMALU_SB_G2          RARM = 74  // ALU_SB_G2
	RARMLDR_SB_G0          RARM = 75  // LDR_SB_G0
	RARMLDR_SB_G1          RARM = 76  // LDR_SB_G1
	RARMLDR_SB_G2          RARM = 77  // LDR_SB_G2
	RARMLDRS_SB_G0         RARM = 78  // LDRS_SB_G0
	RARMLDRS_SB_G1         RARM = 79  // LDRS_SB_G1
	RARMLDRS_SB_G2         RARM = 80  // LDRS_SB_G2
	RARMLDC_SB_G0          RARM = 81  // LDC_SB_G0
	RARMLDC_SB_G1          RARM = 82  // LDC_SB_G1
	RARMLDC_SB_G2          RARM = 83  // LDC_SB_G2
	RARMMOVW_BREL_NC       RARM = 84  // MOVW_BREL_NC
	RARMMOVT_BREL          RARM = 85  // MOVT_BREL
	RARMMOVW_BREL          RARM = 86  // MOVW_BREL
	RARMTHM_MOVW_BREL_NC   RARM = 87  // THM_MOVW_BREL_NC
	RARMTHM_MOVT_BREL      RARM = 88  // THM_MOVT_BREL
	RARMTHM_MOVW_BREL      RARM = 89  // THM_MOVW_BREL
	RARMTLS_GOTDESC        RARM = 90  // TLS_GOTDESC
	RARMTLS_CALL           RARM = 91  // TLS_CALL
	RARMTLS_DESCSEQ        RARM = 92  // TLS_DESCSEQ
	RARMTHM_TLS_CALL       RARM = 93  // THM_TLS_CALL
	RARMPLT32_ABS          RARM = 94  // PLT32_ABS
	RARMGOT_ABS            RARM = 95  // GOT_ABS
	RARMGOT_PREL           RARM = 96  // GOT_PREL
	RARMGOT_BREL12         RARM = 97  // GOT_BREL12
	RARMGOTOFF12           RARM = 98  // GOTOFF12
	RARMGOTRELAX           RARM = 99  // GOTRELAX
	RARMGNU_VTENTRY        RARM = 100 // GNU_VTENTRY
	RARMGNU_VTINHERIT      RARM = 101 // GNU_VTINHERIT
	RARMTHM_JUMP11         RARM = 102 // THM_JUMP11
	RARMTHM_JUMP8          RARM = 103 // THM_JUMP8
	RARMTLS_GD32           RARM = 104 // TLS_GD32
	RARMTLS_LDM32          RARM = 105 // TLS_LDM32
	RARMTLS_LDO32          RARM = 106 // TLS_LDO32
	RARMTLS_IE32           RARM = 107 // TLS_IE32
	RARMTLS_LE32           RARM = 108 // TLS_LE32
	RARMTLS_LDO12          RARM = 109 // TLS_LDO12
	RARMTLS_LE12           RARM = 110 // TLS_LE12
	RARMTLS_IE12GP         RARM = 111 // TLS_IE12GP
	RARMPRIVATE_0          RARM = 112 // PRIVATE_0
	RARMPRIVATE_1          RARM = 113 // PRIVATE_1
	RARMPRIVATE_2          RARM = 114 // PRIVATE_2
	RARMPRIVATE_3          RARM = 115 // PRIVATE_3
	RARMPRIVATE_4          RARM = 116 // PRIVATE_4
	RARMPRIVATE_5          RARM = 117 // PRIVATE_5
	RARMPRIVATE_6          RARM = 118 // PRIVATE_6
	RARMPRIVATE_7          RARM = 119 // PRIVATE_7
	RARMPRIVATE_8          RARM = 120 // PRIVATE_8
	RARMPRIVATE_9          RARM = 121 // PRIVATE_9
	RARMPRIVATE_10         RARM = 122 // PRIVATE_10
	RARMPRIVATE_11         RARM = 123 // PRIVATE_11
	RARMPRIVATE_12         RARM = 124 // PRIVATE_12
	RARMPRIVATE_13         RARM = 125 // PRIVATE_13
	RARMPRIVATE_14         RARM = 126 // PRIVATE_14
	RARMPRIVATE_15         RARM = 127 // PRIVATE_15
	RARMME_TOO             RARM = 128 // ME_TOO
	RARMTHM_TLS_DESCSEQ16  RARM = 129 // THM_TLS_DESCSEQ16
	RARMTHM_TLS_DESCSEQ32  RARM = 130 // THM_TLS_DESCSEQ32
	RARMTHM_GOT_BREL12     RARM = 131 // THM_GOT_BREL12
	RARMTHM_ALU_ABS_G0_NC  RARM = 132 // THM_ALU_ABS_G0_NC
	RARMTHM_ALU_ABS_G1_NC  RARM = 133 // THM_ALU_ABS_G1_NC
	RARMTHM_ALU_ABS_G2_NC  RARM = 134 // THM_ALU_ABS_G2_NC
	RARMTHM_ALU_ABS_G3     RARM = 135 // THM_ALU_ABS_G3
	RARMIRELATIVE          RARM = 160 // IRELATIVE
	RARMRXPC25             RARM = 249 // RXPC25
	RARMRSBREL32           RARM = 250 // RSBREL32
	RARMTHM_RPC22          RARM = 251 // THM_RPC22
	RARMRREL32             RARM = 252 // RREL32
	RARMRABS32             RARM = 253 // RABS32
	RARMRPC24              RARM = 254 // RPC24
	RARMRBASE              RARM = 255 // RBASE
)

// Relocation types for Alpha.
type RAlpha int

const (
	RAlphaNone           RAlpha = 0  // No relocation
	RAlphaREFLONG        RAlpha = 1  // Direct 32 bit
	RAlphaREFQUAD        RAlpha = 2  // Direct 64 bit
	RAlphaGPREL32        RAlpha = 3  // GP relative 32 bit
	RAlphaLITERAL        RAlpha = 4  // GP relative 16 bit w/optimization
	RAlphaLITUSE         RAlpha = 5  // Optimization hint for LITERAL
	RAlphaGPDISP         RAlpha = 6  // Add displacement to GP
	RAlphaBRADDR         RAlpha = 7  // PC+4 relative 23 bit shifted
	RAlphaHINT           RAlpha = 8  // PC+4 relative 16 bit shifted
	RAlphaSREL16         RAlpha = 9  // PC relative 16 bit
	RAlphaSREL32         RAlpha = 10 // PC relative 32 bit
	RAlphaSREL64         RAlpha = 11 // PC relative 64 bit
	RAlphaOP_PUSH        RAlpha = 12 // OP stack push
	RAlphaOP_STORE       RAlpha = 13 // OP stack pop and store
	RAlphaOP_PSUB        RAlpha = 14 // OP stack subtract
	RAlphaOP_PRSHIFT     RAlpha = 15 // OP stack right shift
	RAlphaGPVALUE        RAlpha = 16 // GPVALUE
	RAlphaGPRELHIGH      RAlpha = 17 // GPRELHIGH
	RAlphaGPRELLOW       RAlpha = 18 // GPRELLOW
	RAlphaIMMED_GP_16    RAlpha = 19 // IMMED_GP_16
	RAlphaIMMED_GP_HI32  RAlpha = 20 // IMMED_GP_HI32
	RAlphaIMMED_SCN_HI32 RAlpha = 21 // IMMED_SCN_HI32
	RAlphaIMMED_BR_HI32  RAlpha = 22 // IMMED_BR_HI32
	RAlphaIMMED_LO32     RAlpha = 23 // IMMED_LO32
	RAlphaCOPY           RAlpha = 24 // Copy symbol at runtime
	RAlphaGLOB_DAT       RAlpha = 25 // Create GOT entry
	RAlphaJMP_SLOT       RAlpha = 26 // Create PLT entry
	RAlphaRELATIVE       RAlpha = 27 // Adjust by program base
)

// Relocation types for 386.
type R386 int

const (
	R386None          R386 = 0  // No relocation
	R38632            R386 = 1  // Add symbol value
	R386PC32          R386 = 2  // Add PC-relative symbol value
	R386GOT32         R386 = 3  // Add PC-relative GOT offset
	R386PLT32         R386 = 4  // Add PC-relative PLT offset
	R386COPY          R386 = 5  // Copy data from shared object
	R386GLOB_DAT      R386 = 6  // Set GOT entry to data address
	R386JMP_SLOT      R386 = 7  // Set GOT entry to code address
	R386RELATIVE      R386 = 8  // Add load address of shared object
	R386GOTOFF        R386 = 9  // Add GOT-relative symbol address
	R386GOTPC         R386 = 10 // Add PC-relative GOT table address
	R38632PLT         R386 = 11 // 32PLT
	R386TLS_TPOFF     R386 = 14 // Negative offset in static TLS block
	R386TLS_IE        R386 = 15 // Absolute address of GOT for -ve static TLS
	R386TLS_GOTIE     R386 = 16 // GOT entry for negative static TLS block
	R386TLS_LE        R386 = 17 // Negative offset relative to static TLS
	R386TLS_GD        R386 = 18 // 32 bit offset to GOT (index,off) pair
	R386TLS_LDM       R386 = 19 // 32 bit offset to GOT (index,zero) pair
	R38616            R386 = 20 // 16
	R386PC16          R386 = 21 // PC16
	R3868             R386 = 22 // 8
	R386PC8           R386 = 23 // PC8
	R386TLS_GD_32     R386 = 24 // 32 bit offset to GOT (index,off) pair
	R386TLS_GD_PUSH   R386 = 25 // pushl instruction for Sun ABI GD sequence
	R386TLS_GD_CALL   R386 = 26 // call instruction for Sun ABI GD sequence
	R386TLS_GD_POP    R386 = 27 // popl instruction for Sun ABI GD sequence
	R386TLS_LDM_32    R386 = 28 // 32 bit offset to GOT (index,zero) pair
	R386TLS_LDM_PUSH  R386 = 29 // pushl instruction for Sun ABI LD sequence
	R386TLS_LDM_CALL  R386 = 30 // call instruction for Sun ABI LD sequence
	R386TLS_LDM_POP   R386 = 31 // popl instruction for Sun ABI LD sequence
	R386TLS_LDO_32    R386 = 32 // 32 bit offset from start of TLS block
	R386TLS_IE_32     R386 = 33 // 32 bit offset to GOT static TLS offset entry
	R386TLS_LE_32     R386 = 34 // 32 bit offset within static TLS block
	R386TLS_DTPMOD32  R386 = 35 // GOT entry containing TLS index
	R386TLS_DTPOFF32  R386 = 36 // GOT entry containing TLS offset
	R386TLS_TPOFF32   R386 = 37 // GOT entry of -ve static TLS offset
	R386SIZE32        R386 = 38 // SIZE32
	R386TLS_GOTDESC   R386 = 39 // TLS_GOTDESC
	R386TLS_DESC_CALL R386 = 40 // TLS_DESC_CALL
	R386TLS_DESC      R386 = 41 // TLS_DESC
	R386IRELATIVE     R386 = 42 // IRELATIVE
	R386GOT32X        R386 = 43 // GOT32X
)

// Relocation types for MIPS.
type RMIPS int

const (
	RMIPSNone          RMIPS = 0  // No relocation
	RMIPS16            RMIPS = 1  // 16
	RMIPS32            RMIPS = 2  // 32
	RMIPSREL32         RMIPS = 3  // REL32
	RMIPS26            RMIPS = 4  // 26
	RMIPSHI16          RMIPS = 5  // high 16 bits of symbol value
	RMIPSLO16          RMIPS = 6  // low 16 bits of symbol value
	RMIPSGPREL16       RMIPS = 7  // GP-relative reference
	RMIPSLITERAL       RMIPS = 8  // Reference to literal section
	RMIPSGOT16         RMIPS = 9  // Reference to global offset table
	RMIPSPC16          RMIPS = 10 // 16 bit PC relative reference
	RMIPSCALL16        RMIPS = 11 // 16 bit call through glbl offset tbl
	RMIPSGPREL32       RMIPS = 12 // GPREL32
	RMIPSSHIFT5        RMIPS = 16 // SHIFT5
	RMIPSSHIFT6        RMIPS = 17 // SHIFT6
	RMIPS64            RMIPS = 18 // 64
	RMIPSGOT_DISP      RMIPS = 19 // GOT_DISP
	RMIPSGOT_PAGE      RMIPS = 20 // GOT_PAGE
	RMIPSGOT_OFST      RMIPS = 21 // GOT_OFST
	RMIPSGOT_HI16      RMIPS = 22 // GOT_HI16
	RMIPSGOT_LO16      RMIPS = 23 // GOT_LO16
	RMIPSSUB           RMIPS = 24 // SUB
	RMIPSINSERT_A      RMIPS = 25 // INSERT_A
	RMIPSINSERT_B      RMIPS = 26 // INSERT_B
	RMIPSDELETE        RMIPS = 27 // DELETE
	RMIPSHIGHER        RMIPS = 28 // HIGHER
	RMIPSHIGHEST       RMIPS = 29 // HIGHEST
	RMIPSCALL_HI16     RMIPS = 30 // CALL_HI16
	RMIPSCALL_LO16     RMIPS = 31 // CALL_LO16
	RMIPSSCN_DISP      RMIPS = 32 // SCN_DISP
	RMIPSREL16         RMIPS = 33 // REL16
	RMIPSADD_IMMEDIATE RMIPS = 34 // ADD_IMMEDIATE
	RMIPSPJUMP         RMIPS = 35 // PJUMP
	RMIPSRELGOT        RMIPS = 36 // RELGOT
	RMIPSJALR          RMIPS = 37 // JALR

	RMIPSTLS_DTPMOD32    RMIPS = 38 // Module number 32 bit
	RMIPSTLS_DTPREL32    RMIPS = 39 // Module-relative offset 32 bit
	RMIPSTLS_DTPMOD64    RMIPS = 40 // Module number 64 bit
	RMIPSTLS_DTPREL64    RMIPS = 41 // Module-relative offset 64 bit
	RMIPSTLS_GD          RMIPS = 42 // 16 bit GOT offset for GD
	RMIPSTLS_LDM         RMIPS = 43 // 16 bit GOT offset for LDM
	RMIPSTLS_DTPREL_HI16 RMIPS = 44 // Module-relative offset, high 16 bits
	RMIPSTLS_DTPREL_LO16 RMIPS = 45 // Module-relative offset, low 16 bits
	RMIPSTLS_GOTTPREL    RMIPS = 46 // 16 bit GOT offset for IE
	RMIPSTLS_TPREL32     RMIPS = 47 // TP-relative offset, 32 bit
	RMIPSTLS_TPREL64     RMIPS = 48 // TP-relative offset, 64 bit
	RMIPSTLS_TPREL_HI16  RMIPS = 49 // TP-relative offset, high 16 bits
	RMIPSTLS_TPREL_LO16  RMIPS = 50 // TP-relative offset, low 16 bits

	RMIPSPC32 RMIPS = 248 // 32 bit PC relative reference
)

// Relocation types for LoongArch.
type RLoongArch int

const (
	RLoongArchNone                       RLoongArch = 0   // None
	RLoongArch32                         RLoongArch = 1   // 32
	RLoongArch64                         RLoongArch = 2   // 64
	RLoongArchRELATIVE                   RLoongArch = 3   // RELATIVE
	RLoongArchCOPY                       RLoongArch = 4   // COPY
	RLoongArchJUMP_SLOT                  RLoongArch = 5   // JUMP_SLOT
	RLoongArchTLS_DTPMOD32               RLoongArch = 6   // TLS_DTPMOD32
	RLoongArchTLS_DTPMOD64               RLoongArch = 7   // TLS_DTPMOD64
	RLoongArchTLS_DTPREL32               RLoongArch = 8   // TLS_DTPREL32
	RLoongArchTLS_DTPREL64               RLoongArch = 9   // TLS_DTPREL64
	RLoongArchTLS_TPREL32                RLoongArch = 10  // TLS_TPREL32
	RLoongArchTLS_TPREL64                RLoongArch = 11  // TLS_TPREL64
	RLoongArchIRELATIVE                  RLoongArch = 12  // IRELATIVE
	RLoongArchMARK_LA                    RLoongArch = 20  // MARK_LA
	RLoongArchMARK_PCREL                 RLoongArch = 21  // MARK_PCREL
	RLoongArchSOP_PUSH_PCREL             RLoongArch = 22  // SOP_PUSH_PCREL
	RLoongArchSOP_PUSH_ABSOLUTE          RLoongArch = 23  // SOP_PUSH_ABSOLUTE
	RLoongArchSOP_PUSH_DUP               RLoongArch = 24  // SOP_PUSH_DUP
	RLoongArchSOP_PUSH_GPREL             RLoongArch = 25  // SOP_PUSH_GPREL
	RLoongArchSOP_PUSH_TLS_TPREL         RLoongArch = 26  // SOP_PUSH_TLS_TPREL
	RLoongArchSOP_PUSH_TLS_GOT           RLoongArch = 27  // SOP_PUSH_TLS_GOT
	RLoongArchSOP_PUSH_TLS_GD            RLoongArch = 28  // SOP_PUSH_TLS_GD
	RLoongArchSOP_PUSH_PLT_PCREL         RLoongArch = 29  // SOP_PUSH_PLT_PCREL
	RLoongArchSOP_ASSERT                 RLoongArch = 30  // SOP_ASSERT
	RLoongArchSOP_NOT                    RLoongArch = 31  // SOP_NOT
	RLoongArchSOP_SUB                    RLoongArch = 32  // SOP_SUB
	RLoongArchSOP_SL                     RLoongArch = 33  // SOP_SL
	RLoongArchSOP_SR                     RLoongArch = 34  // SOP_SR
	RLoongArchSOP_ADD                    RLoongArch = 35  // SOP_ADD
	RLoongArchSOP_AND                    RLoongArch = 36  // SOP_AND
	RLoongArchSOP_IF_ELSE                RLoongArch = 37  // SOP_IF_ELSE
	RLoongArchSOP_POP_32_S_10_5          RLoongArch = 38  // SOP_POP_32_S_10_5
	RLoongArchSOP_POP_32_U_10_12         RLoongArch = 39  // SOP_POP_32_U_10_12
	RLoongArchSOP_POP_32_S_10_12         RLoongArch = 40  // SOP_POP_32_S_10_12
	RLoongArchSOP_POP_32_S_10_16         RLoongArch = 41  // SOP_POP_32_S_10_16
	RLoongArchSOP_POP_32_S_10_16_S2      RLoongArch = 42  // SOP_POP_32_S_10_16_S2
	RLoongArchSOP_POP_32_S_5_20          RLoongArch = 43  // SOP_POP_32_S_5_20
	RLoongArchSOP_POP_32_S_0_5_10_16_S2  RLoongArch = 44  // SOP_POP_32_S_0_5_10_16_S2
	RLoongArchSOP_POP_32_S_0_10_10_16_S2 RLoongArch = 45  // SOP_POP_32_S_0_10_10_16_S2
	RLoongArchSOP_POP_32_U               RLoongArch = 46  // SOP_POP_32_U
	RLoongArchADD8                       RLoongArch = 47  // ADD8
	RLoongArchADD16                      RLoongArch = 48  // ADD16
	RLoongArchADD24                      RLoongArch = 49  // ADD24
	RLoongArchADD32                      RLoongArch = 50  // ADD32
	RLoongArchADD64                      RLoongArch = 51  // ADD64
	RLoongArchSUB8                       RLoongArch = 52  // SUB8
	RLoongArchSUB16                      RLoongArch = 53  // SUB16
	RLoongArchSUB24                      RLoongArch = 54  // SUB24
	RLoongArchSUB32                      RLoongArch = 55  // SUB32
	RLoongArchSUB64                      RLoongArch = 56  // SUB64
	RLoongArchGNU_VTINHERIT              RLoongArch = 57  // GNU_VTINHERIT
	RLoongArchGNU_VTENTRY                RLoongArch = 58  // GNU_VTENTRY
	RLoongArchB16                        RLoongArch = 64  // B16
	RLoongArchB21                        RLoongArch = 65  // B21
	RLoongArchB26                        RLoongArch = 66  // B26
	RLoongArchABS_HI20                   RLoongArch = 67  // ABS_HI20
	RLoongArchABS_LO12                   RLoongArch = 68  // ABS_LO12
	RLoongArchABS64_LO20                 RLoongArch = 69  // ABS64_LO20
	RLoongArchABS64_HI12                 RLoongArch = 70  // ABS64_HI12
	RLoongArchPCALA_HI20                 RLoongArch = 71  // PCALA_HI20
	RLoongArchPCALA_LO12                 RLoongArch = 72  // PCALA_LO12
	RLoongArchPCALA64_LO20               RLoongArch = 73  // PCALA64_LO20
	RLoongArchPCALA64_HI12               RLoongArch = 74  // PCALA64_HI12
	RLoongArchGOT_PC_HI20                RLoongArch = 75  // GOT_PC_HI20
	RLoongArchGOT_PC_LO12                RLoongArch = 76  // GOT_PC_LO12
	RLoongArchGOT64_PC_LO20              RLoongArch = 77  // GOT64_PC_LO20
	RLoongArchGOT64_PC_HI12              RLoongArch = 78  // GOT64_PC_HI12
	RLoongArchGOT_HI20                   RLoongArch = 79  // GOT_HI20
	RLoongArchGOT_LO12                   RLoongArch = 80  // GOT_LO12
	RLoongArchGOT64_LO20                 RLoongArch = 81  // GOT64_LO20
	RLoongArchGOT64_HI12                 RLoongArch = 82  // GOT64_HI12
	RLoongArchTLS_LE_HI20                RLoongArch = 83  // TLS_LE_HI20
	RLoongArchTLS_LE_LO12                RLoongArch = 84  // TLS_LE_LO12
	RLoongArchTLS_LE64_LO20              RLoongArch = 85  // TLS_LE64_LO20
	RLoongArchTLS_LE64_HI12              RLoongArch = 86  // TLS_LE64_HI12
	RLoongArchTLS_IE_PC_HI20             RLoongArch = 87  // TLS_IE_PC_HI20
	RLoongArchTLS_IE_PC_LO12             RLoongArch = 88  // TLS_IE_PC_LO12
	RLoongArchTLS_IE64_PC_LO20           RLoongArch = 89  // TLS_IE64_PC_LO20
	RLoongArchTLS_IE64_PC_HI12           RLoongArch = 90  // TLS_IE64_PC_HI12
	RLoongArchTLS_IE_HI20                RLoongArch = 91  // TLS_IE_HI20
	RLoongArchTLS_IE_LO12                RLoongArch = 92  // TLS_IE_LO12
	RLoongArchTLS_IE64_LO20              RLoongArch = 93  // TLS_IE64_LO20
	RLoongArchTLS_IE64_HI12              RLoongArch = 94  // TLS_IE64_HI12
	RLoongArchTLS_LD_PC_HI20             RLoongArch = 95  // TLS_LD_PC_HI20
	RLoongArchTLS_LD_HI20                RLoongArch = 96  // TLS_LD_HI20
	RLoongArchTLS_GD_PC_HI20             RLoongArch = 97  // TLS_GD_PC_HI20
	RLoongArchTLS_GD_HI20                RLoongArch = 98  // TLS_GD_HI20
	RLoongArch32_PCREL                   RLoongArch = 99  // 32_PCREL
	RLoongArchRELAX                      RLoongArch = 100 // RELAX
	RLoongArchDELETE                     RLoongArch = 101 // DELETE
	RLoongArchALIGN                      RLoongArch = 102 // ALIGN
	RLoongArchPCREL20_S2                 RLoongArch = 103 // PCREL20_S2
	RLoongArchCFA                        RLoongArch = 104 // CFA
	RLoongArchADD6                       RLoongArch = 105 // ADD6
	RLoongArchSUB6                       RLoongArch = 106 // SUB6
	RLoongArchADD_ULEB128                RLoongArch = 107 // ADD_ULEB128
	RLoongArchSUB_ULEB128                RLoongArch = 108 // SUB_ULEB128
	RLoongArch64_PCREL                   RLoongArch = 109 // 64_PCREL
)

// Relocation types for PowerPC.
//
// Values that are shared by both RPPC and R_PPC64 are prefixed with
// R_POWERPC_ in the ELF standard. For the RPPC type, the relevant
// shared relocations have been renamed with the prefix R_PPC_.
// The original name follows the value in a comment.
type RPPC int

const (
	RPPCNone            RPPC = 0   // None
	RPPCADDR32          RPPC = 1   // ADDR32
	RPPCADDR24          RPPC = 2   // ADDR24
	RPPCADDR16          RPPC = 3   // ADDR16
	RPPCADDR16_LO       RPPC = 4   // ADDR16_LO
	RPPCADDR16_HI       RPPC = 5   // ADDR16_HI
	RPPCADDR16_HA       RPPC = 6   // ADDR16_HA
	RPPCADDR14          RPPC = 7   // ADDR14
	RPPCADDR14_BRTAKEN  RPPC = 8   // ADDR14_BRTAKEN
	RPPCADDR14_BRNTAKEN RPPC = 9   // ADDR14_BRNTAKEN
	RPPCREL24           RPPC = 10  // REL24
	RPPCREL14           RPPC = 11  // REL14
	RPPCREL14_BRTAKEN   RPPC = 12  // REL14_BRTAKEN
	RPPCREL14_BRNTAKEN  RPPC = 13  // REL14_BRNTAKEN
	RPPCGOT16           RPPC = 14  // GOT16
	RPPCGOT16_LO        RPPC = 15  // GOT16_LO
	RPPCGOT16_HI        RPPC = 16  // GOT16_HI
	RPPCGOT16_HA        RPPC = 17  // GOT16_HA
	RPPCPLTREL24        RPPC = 18  // PLTREL24
	RPPCCOPY            RPPC = 19  // COPY
	RPPCGLOB_DAT        RPPC = 20  // GLOB_DAT
	RPPCJMP_SLOT        RPPC = 21  // JMP_SLOT
	RPPCRELATIVE        RPPC = 22  // RELATIVE
	RPPCLOCAL24PC       RPPC = 23  // LOCAL24PC
	RPPCUADDR32         RPPC = 24  // UADDR32
	RPPCUADDR16         RPPC = 25  // UADDR16
	RPPCREL32           RPPC = 26  // REL32
	RPPCPLT32           RPPC = 27  // PLT32
	RPPCPLTREL32        RPPC = 28  // PLTREL32
	RPPCPLT16_LO        RPPC = 29  // PLT16_LO
	RPPCPLT16_HI        RPPC = 30  // PLT16_HI
	RPPCPLT16_HA        RPPC = 31  // PLT16_HA
	RPPCSDAREL16        RPPC = 32  // SDAREL16
	RPPCSECTOFF         RPPC = 33  // SECTOFF
	RPPCSECTOFF_LO      RPPC = 34  // SECTOFF_LO
	RPPCSECTOFF_HI      RPPC = 35  // SECTOFF_HI
	RPPCSECTOFF_HA      RPPC = 36  // SECTOFF_HA
	RPPCTLS             RPPC = 67  // TLS
	RPPCDTPMOD32        RPPC = 68  // DTPMOD32
	RPPCTPREL16         RPPC = 69  // TPREL16
	RPPCTPREL16_LO      RPPC = 70  // TPREL16_LO
	RPPCTPREL16_HI      RPPC = 71  // TPREL16_HI
	RPPCTPREL16_HA      RPPC = 72  // TPREL16_HA
	RPPCTPREL32         RPPC = 73  // TPREL32
	RPPCDTPREL16        RPPC = 74  // DTPREL16
	RPPCDTPREL16_LO     RPPC = 75  // DTPREL16_LO
	RPPCDTPREL16_HI     RPPC = 76  // DTPREL16_HI
	RPPCDTPREL16_HA     RPPC = 77  // DTPREL16_HA
	RPPCDTPREL32        RPPC = 78  // DTPREL32
	RPPCGOT_TLSGD16     RPPC = 79  // GOT_TLSGD16
	RPPCGOT_TLSGD16_LO  RPPC = 80  // GOT_TLSGD16_LO
	RPPCGOT_TLSGD16_HI  RPPC = 81  // GOT_TLSGD16_HI
	RPPCGOT_TLSGD16_HA  RPPC = 82  // GOT_TLSGD16_HA
	RPPCGOT_TLSLD16     RPPC = 83  // GOT_TLSLD16
	RPPCGOT_TLSLD16_LO  RPPC = 84  // GOT_TLSLD16_LO
	RPPCGOT_TLSLD16_HI  RPPC = 85  // GOT_TLSLD16_HI
	RPPCGOT_TLSLD16_HA  RPPC = 86  // GOT_TLSLD16_HA
	RPPCGOT_TPREL16     RPPC = 87  // GOT_TPREL16
	RPPCGOT_TPREL16_LO  RPPC = 88  // GOT_TPREL16_LO
	RPPCGOT_TPREL16_HI  RPPC = 89  // GOT_TPREL16_HI
	RPPCGOT_TPREL16_HA  RPPC = 90  // GOT_TPREL16_HA
	RPPCEMB_NADDR32     RPPC = 101 // EMB_NADDR32
	RPPCEMB_NADDR16     RPPC = 102 // EMB_NADDR16
	RPPCEMB_NADDR16_LO  RPPC = 103 // EMB_NADDR16_LO
	RPPCEMB_NADDR16_HI  RPPC = 104 // EMB_NADDR16_HI
	RPPCEMB_NADDR16_HA  RPPC = 105 // EMB_NADDR16_HA
	RPPCEMB_SDAI16      RPPC = 106 // EMB_SDAI16
	RPPCEMB_SDA2I16     RPPC = 107 // EMB_SDA2I16
	RPPCEMB_SDA2REL     RPPC = 108 // EMB_SDA2REL
	RPPCEMB_SDA21       RPPC = 109 // EMB_SDA21
	RPPCEMB_MRKREF      RPPC = 110 // EMB_MRKREF
	RPPCEMB_RELSEC16    RPPC = 111 // EMB_RELSEC16
	RPPCEMB_RELST_LO    RPPC = 112 // EMB_RELST_LO
	RPPCEMB_RELST_HI    RPPC = 113 // EMB_RELST_HI
	RPPCEMB_RELST_HA    RPPC = 114 // EMB_RELST_HA
	RPPCEMB_BIT_FLD     RPPC = 115 // EMB_BIT_FLD
	RPPCEMB_RELSDA      RPPC = 116 // EMB_RELSDA
)

// Relocation types for 64-bit PowerPC or Power Architecture processors.
//
// Values that are shared by both R_PPC and RPPC64 are prefixed with
// R_POWERPC_ in the ELF standard. For the RPPC64 type, the relevant
// shared relocations have been renamed with the prefix R_PPC64_.
// The original name follows the value in a comment.
type RPPC64 int

const (
	RPPC64None               RPPC64 = 0   // None
	RPPC64ADDR32             RPPC64 = 1   // ADDR32
	RPPC64ADDR24             RPPC64 = 2   // ADDR24
	RPPC64ADDR16             RPPC64 = 3   // ADDR16
	RPPC64ADDR16_LO          RPPC64 = 4   // ADDR16_LO
	RPPC64ADDR16_HI          RPPC64 = 5   // ADDR16_HI
	RPPC64ADDR16_HA          RPPC64 = 6   // ADDR16_HA
	RPPC64ADDR14             RPPC64 = 7   // ADDR14
	RPPC64ADDR14_BRTAKEN     RPPC64 = 8   // ADDR14_BRTAKEN
	RPPC64ADDR14_BRNTAKEN    RPPC64 = 9   // ADDR14_BRNTAKEN
	RPPC64REL24              RPPC64 = 10  // REL24
	RPPC64REL14              RPPC64 = 11  // REL14
	RPPC64REL14_BRTAKEN      RPPC64 = 12  // REL14_BRTAKEN
	RPPC64REL14_BRNTAKEN     RPPC64 = 13  // REL14_BRNTAKEN
	RPPC64GOT16              RPPC64 = 14  // GOT16
	RPPC64GOT16_LO           RPPC64 = 15  // GOT16_LO
	RPPC64GOT16_HI           RPPC64 = 16  // GOT16_HI
	RPPC64GOT16_HA           RPPC64 = 17  // GOT16_HA
	RPPC64COPY               RPPC64 = 19  // COPY
	RPPC64GLOB_DAT           RPPC64 = 20  // GLOB_DAT
	RPPC64JMP_SLOT           RPPC64 = 21  // JMP_SLOT
	RPPC64RELATIVE           RPPC64 = 22  // RELATIVE
	RPPC64UADDR32            RPPC64 = 24  // UADDR32
	RPPC64UADDR16            RPPC64 = 25  // UADDR16
	RPPC64REL32              RPPC64 = 26  // REL32
	RPPC64PLT32              RPPC64 = 27  // PLT32
	RPPC64PLTREL32           RPPC64 = 28  // PLTREL32
	RPPC64PLT16_LO           RPPC64 = 29  // PLT16_LO
	RPPC64PLT16_HI           RPPC64 = 30  // PLT16_HI
	RPPC64PLT16_HA           RPPC64 = 31  // PLT16_HA
	RPPC64SECTOFF            RPPC64 = 33  // SECTOFF
	RPPC64SECTOFF_LO         RPPC64 = 34  // SECTOFF_LO
	RPPC64SECTOFF_HI         RPPC64 = 35  // SECTOFF_HI
	RPPC64SECTOFF_HA         RPPC64 = 36  // SECTOFF_HA
	RPPC64REL30              RPPC64 = 37  // REL30
	RPPC64ADDR64             RPPC64 = 38  // ADDR64
	RPPC64ADDR16_HIGHER      RPPC64 = 39  // ADDR16_HIGHER
	RPPC64ADDR16_HIGHERA     RPPC64 = 40  // ADDR16_HIGHERA
	RPPC64ADDR16_HIGHEST     RPPC64 = 41  // ADDR16_HIGHEST
	RPPC64ADDR16_HIGHESTA    RPPC64 = 42  // ADDR16_HIGHESTA
	RPPC64UADDR64            RPPC64 = 43  // UADDR64
	RPPC64REL64              RPPC64 = 44  // REL64
	RPPC64PLT64              RPPC64 = 45  // PLT64
	RPPC64PLTREL64           RPPC64 = 46  // PLTREL64
	RPPC64TOC16              RPPC64 = 47  // TOC16
	RPPC64TOC16_LO           RPPC64 = 48  // TOC16_LO
	RPPC64TOC16_HI           RPPC64 = 49  // TOC16_HI
	RPPC64TOC16_HA           RPPC64 = 50  // TOC16_HA
	RPPC64TOC                RPPC64 = 51  // TOC
	RPPC64PLTGOT16           RPPC64 = 52  // PLTGOT16
	RPPC64PLTGOT16_LO        RPPC64 = 53  // PLTGOT16_LO
	RPPC64PLTGOT16_HI        RPPC64 = 54  // PLTGOT16_HI
	RPPC64PLTGOT16_HA        RPPC64 = 55  // PLTGOT16_HA
	RPPC64ADDR16_DS          RPPC64 = 56  // ADDR16_DS
	RPPC64ADDR16_LO_DS       RPPC64 = 57  // ADDR16_LO_DS
	RPPC64GOT16_DS           RPPC64 = 58  // GOT16_DS
	RPPC64GOT16_LO_DS        RPPC64 = 59  // GOT16_LO_DS
	RPPC64PLT16_LO_DS        RPPC64 = 60  // PLT16_LO_DS
	RPPC64SECTOFF_DS         RPPC64 = 61  // SECTOFF_DS
	RPPC64SECTOFF_LO_DS      RPPC64 = 62  // SECTOFF_LO_DS
	RPPC64TOC16_DS           RPPC64 = 63  // TOC16_DS
	RPPC64TOC16_LO_DS        RPPC64 = 64  // TOC16_LO_DS
	RPPC64PLTGOT16_DS        RPPC64 = 65  // PLTGOT16_DS
	RPPC64PLTGOT_LO_DS       RPPC64 = 66  // PLTGOT_LO_DS
	RPPC64TLS                RPPC64 = 67  // TLS
	RPPC64DTPMOD64           RPPC64 = 68  // DTPMOD64
	RPPC64TPREL16            RPPC64 = 69  // TPREL16
	RPPC64TPREL16_LO         RPPC64 = 70  // TPREL16_LO
	RPPC64TPREL16_HI         RPPC64 = 71  // TPREL16_HI
	RPPC64TPREL16_HA         RPPC64 = 72  // TPREL16_HA
	RPPC64TPREL64            RPPC64 = 73  // TPREL64
	RPPC64DTPREL16           RPPC64 = 74  // DTPREL16
	RPPC64DTPREL16_LO        RPPC64 = 75  // DTPREL16_LO
	RPPC64DTPREL16_HI        RPPC64 = 76  // DTPREL16_HI
	RPPC64DTPREL16_HA        RPPC64 = 77  // DTPREL16_HA
	RPPC64DTPREL64           RPPC64 = 78  // DTPREL64
	RPPC64GOT_TLSGD16        RPPC64 = 79  // GOT_TLSGD16
	RPPC64GOT_TLSGD16_LO     RPPC64 = 80  // GOT_TLSGD16_LO
	RPPC64GOT_TLSGD16_HI     RPPC64 = 81  // GOT_TLSGD16_HI
	RPPC64GOT_TLSGD16_HA     RPPC64 = 82  // GOT_TLSGD16_HA
	RPPC64GOT_TLSLD16        RPPC64 = 83  // GOT_TLSLD16
	RPPC64GOT_TLSLD16_LO     RPPC64 = 84  // GOT_TLSLD16_LO
	RPPC64GOT_TLSLD16_HI     RPPC64 = 85  // GOT_TLSLD16_HI
	RPPC64GOT_TLSLD16_HA     RPPC64 = 86  // GOT_TLSLD16_HA
	RPPC64GOT_TPREL16_DS     RPPC64 = 87  // GOT_TPREL16_DS
	RPPC64GOT_TPREL16_LO_DS  RPPC64 = 88  // GOT_TPREL16_LO_DS
	RPPC64GOT_TPREL16_HI     RPPC64 = 89  // GOT_TPREL16_HI
	RPPC64GOT_TPREL16_HA     RPPC64 = 90  // GOT_TPREL16_HA
	RPPC64GOT_DTPREL16_DS    RPPC64 = 91  // GOT_DTPREL16_DS
	RPPC64GOT_DTPREL16_LO_DS RPPC64 = 92  // GOT_DTPREL16_LO_DS
	RPPC64GOT_DTPREL16_HI    RPPC64 = 93  // GOT_DTPREL16_HI
	RPPC64GOT_DTPREL16_HA    RPPC64 = 94  // GOT_DTPREL16_HA
	RPPC64TPREL16_DS         RPPC64 = 95  // TPREL16_DS
	RPPC64TPREL16_LO_DS      RPPC64 = 96  // TPREL16_LO_DS
	RPPC64TPREL16_HIGHER     RPPC64 = 97  // TPREL16_HIGHER
	RPPC64TPREL16_HIGHERA    RPPC64 = 98  // TPREL16_HIGHERA
	RPPC64TPREL16_HIGHEST    RPPC64 = 99  // TPREL16_HIGHEST
	RPPC64TPREL16_HIGHESTA   RPPC64 = 10  // TPREL16_HIGHESTA
	RPPC64DTPREL16_DS        RPPC64 = 10  // DTPREL16_DS
	RPPC64DTPREL16_LO_DS     RPPC64 = 10  // DTPREL16_LO_DS
	RPPC64DTPREL16_HIGHER    RPPC64 = 10  // DTPREL16_HIGHER
	RPPC64DTPREL16_HIGHERA   RPPC64 = 10  // DTPREL16_HIGHERA
	RPPC64DTPREL16_HIGHEST   RPPC64 = 10  // DTPREL16_HIGHEST
	RPPC64DTPREL16_HIGHESTA  RPPC64 = 10  // DTPREL16_HIGHESTA
	RPPC64TLSGD              RPPC64 = 10  // TLSGD
	RPPC64TLSLD              RPPC64 = 10  // TLSLD
	RPPC64TOCSAVE            RPPC64 = 10  // TOCSAVE
	RPPC64ADDR16_HIGH        RPPC64 = 11  // ADDR16_HIGH
	RPPC64ADDR16_HIGHA       RPPC64 = 11  // ADDR16_HIGHA
	RPPC64TPREL16_HIGH       RPPC64 = 11  // TPREL16_HIGH
	RPPC64TPREL16_HIGHA      RPPC64 = 11  // TPREL16_HIGHA
	RPPC64DTPREL16_HIGH      RPPC64 = 11  // DTPREL16_HIGH
	RPPC64DTPREL16_HIGHA     RPPC64 = 11  // DTPREL16_HIGHA
	RPPC64REL24_NOTOC        RPPC64 = 11  // REL24_NOTOC
	RPPC64ADDR64_LOCAL       RPPC64 = 11  // ADDR64_LOCAL
	RPPC64ENTRY              RPPC64 = 11  // ENTRY
	RPPC64PLTSEQ             RPPC64 = 11  // PLTSEQ
	RPPC64PLTCALL            RPPC64 = 12  // PLTCALL
	RPPC64PLTSEQ_NOTOC       RPPC64 = 12  // PLTSEQ_NOTOC
	RPPC64PLTCALL_NOTOC      RPPC64 = 12  // PLTCALL_NOTOC
	RPPC64PCREL_OPT          RPPC64 = 12  // PCREL_OPT
	RPPC64REL24_P9NOTOC      RPPC64 = 12  // REL24_P9NOTOC
	RPPC64D34                RPPC64 = 12  // D34
	RPPC64D34_LO             RPPC64 = 12  // D34_LO
	RPPC64D34_HI30           RPPC64 = 13  // D34_HI30
	RPPC64D34_HA30           RPPC64 = 13  // D34_HA30
	RPPC64PCREL34            RPPC64 = 13  // PCREL34
	RPPC64GOT_PCREL34        RPPC64 = 13  // GOT_PCREL34
	RPPC64PLT_PCREL34        RPPC64 = 13  // PLT_PCREL34
	RPPC64PLT_PCREL34_NOTOC  RPPC64 = 13  // PLT_PCREL34_NOTOC
	RPPC64ADDR16_HIGHER34    RPPC64 = 13  // ADDR16_HIGHER34
	RPPC64ADDR16_HIGHERA34   RPPC64 = 13  // ADDR16_HIGHERA34
	RPPC64ADDR16_HIGHEST34   RPPC64 = 13  // ADDR16_HIGHEST34
	RPPC64ADDR16_HIGHESTA34  RPPC64 = 13  // ADDR16_HIGHESTA34
	RPPC64REL16_HIGHER34     RPPC64 = 14  // REL16_HIGHER34
	RPPC64REL16_HIGHERA34    RPPC64 = 14  // REL16_HIGHERA34
	RPPC64REL16_HIGHEST34    RPPC64 = 14  // REL16_HIGHEST34
	RPPC64REL16_HIGHESTA34   RPPC64 = 14  // REL16_HIGHESTA34
	RPPC64D28                RPPC64 = 14  // D28
	RPPC64PCREL28            RPPC64 = 14  // PCREL28
	RPPC64TPREL34            RPPC64 = 14  // TPREL34
	RPPC64DTPREL34           RPPC64 = 14  // DTPREL34
	RPPC64GOT_TLSGD_PCREL34  RPPC64 = 14  // GOT_TLSGD_PCREL34
	RPPC64GOT_TLSLD_PCREL34  RPPC64 = 14  // GOT_TLSLD_PCREL34
	RPPC64GOT_TPREL_PCREL34  RPPC64 = 15  // GOT_TPREL_PCREL34
	RPPC64GOT_DTPREL_PCREL34 RPPC64 = 15  // GOT_DTPREL_PCREL34
	RPPC64REL16_HIGH         RPPC64 = 24  // REL16_HIGH
	RPPC64REL16_HIGHA        RPPC64 = 24  // REL16_HIGHA
	RPPC64REL16_HIGHER       RPPC64 = 24  // REL16_HIGHER
	RPPC64REL16_HIGHERA      RPPC64 = 24  // REL16_HIGHERA
	RPPC64REL16_HIGHEST      RPPC64 = 24  // REL16_HIGHEST
	RPPC64REL16_HIGHESTA     RPPC64 = 24  // REL16_HIGHESTA
	RPPC64REL16DX_HA         RPPC64 = 246 // REL16DX_HA
	RPPC64JMP_IREL           RPPC64 = 24  // JMP_IREL
	RPPC64IRELATIVE          RPPC64 = 248 // IRELATIVE
	RPPC64REL16              RPPC64 = 249 // REL16
	RPPC64REL16_LO           RPPC64 = 250 // REL16_LO
	RPPC64REL16_HI           RPPC64 = 251 // REL16_HI
	RPPC64REL16_HA           RPPC64 = 252 // REL16_HA
	RPPC64GNU_VTINHERIT      RPPC64 = 25  // GNU_VTINHERIT
	RPPC64GNU_VTENTRY        RPPC64 = 25  // GNU_VTENTRY
)

// Relocation types for RISC-V processors.
type RRISCV int

const (
	RRISCVNone          RRISCV = 0  // No relocation
	RRISCV32            RRISCV = 1  // Add 32 bit zero extended symbol value
	RRISCV64            RRISCV = 2  // Add 64 bit symbol value
	RRISCVRELATIVE      RRISCV = 3  // Add load address of shared object
	RRISCVCOPY          RRISCV = 4  // Copy data from shared object
	RRISCVJUMP_SLOT     RRISCV = 5  // Set GOT entry to code address
	RRISCVTLS_DTPMOD32  RRISCV = 6  // 32 bit ID of module containing symbol
	RRISCVTLS_DTPMOD64  RRISCV = 7  // ID of module containing symbol
	RRISCVTLS_DTPREL32  RRISCV = 8  // 32 bit relative offset in TLS block
	RRISCVTLS_DTPREL64  RRISCV = 9  // Relative offset in TLS block
	RRISCVTLS_TPREL32   RRISCV = 10 // 32 bit relative offset in static TLS block
	RRISCVTLS_TPREL64   RRISCV = 11 // Relative offset in static TLS block
	RRISCVBRANCH        RRISCV = 16 // PC-relative branch
	RRISCVJAL           RRISCV = 17 // PC-relative jump
	RRISCVCALL          RRISCV = 18 // PC-relative call
	RRISCVCALL_PLT      RRISCV = 19 // PC-relative call (PLT)
	RRISCVGOT_HI20      RRISCV = 20 // PC-relative GOT reference
	RRISCVTLS_GOT_HI20  RRISCV = 21 // PC-relative TLS IE GOT offset
	RRISCVTLS_GD_HI20   RRISCV = 22 // PC-relative TLS GD reference
	RRISCVPCREL_HI20    RRISCV = 23 // PC-relative reference
	RRISCVPCREL_LO12_I  RRISCV = 24 // PC-relative reference
	RRISCVPCREL_LO12_S  RRISCV = 25 // PC-relative reference
	RRISCVHI20          RRISCV = 26 // Absolute address
	RRISCVLO12_I        RRISCV = 27 // Absolute address
	RRISCVLO12_S        RRISCV = 28 // Absolute address
	RRISCVTPREL_HI20    RRISCV = 29 // TLS LE thread offset
	RRISCVTPREL_LO12_I  RRISCV = 30 // TLS LE thread offset
	RRISCVTPREL_LO12_S  RRISCV = 31 // TLS LE thread offset
	RRISCVTPREL_ADD     RRISCV = 32 // TLS LE thread usage
	RRISCVADD8          RRISCV = 33 // 8-bit label addition
	RRISCVADD16         RRISCV = 34 // 16-bit label addition
	RRISCVADD32         RRISCV = 35 // 32-bit label addition
	RRISCVADD64         RRISCV = 36 // 64-bit label addition
	RRISCVSUB8          RRISCV = 37 // 8-bit label subtraction
	RRISCVSUB16         RRISCV = 38 // 16-bit label subtraction
	RRISCVSUB32         RRISCV = 39 // 32-bit label subtraction
	RRISCVSUB64         RRISCV = 40 // 64-bit label subtraction
	RRISCVGNU_VTINHERIT RRISCV = 41 // GNU C++ vtable hierarchy
	RRISCVGNU_VTENTRY   RRISCV = 42 // GNU C++ vtable member usage
	RRISCVALIGN         RRISCV = 43 // Alignment statement
	RRISCVRVC_BRANCH    RRISCV = 44 // PC-relative branch offset
	RRISCVRVC_JUMP      RRISCV = 45 // PC-relative jump offset
	RRISCVRVC_LUI       RRISCV = 46 // Absolute address
	RRISCVGPREL_I       RRISCV = 47 // GP-relative reference
	RRISCVGPREL_S       RRISCV = 48 // GP-relative reference
	RRISCVTPREL_I       RRISCV = 49 // TP-relative TLS LE load
	RRISCVTPREL_S       RRISCV = 50 // TP-relative TLS LE store
	RRISCVRELAX         RRISCV = 51 // Instruction pair can be relaxed
	RRISCVSUB6          RRISCV = 52 // Local label subtraction
	RRISCVSET6          RRISCV = 53 // Local label subtraction
	RRISCVSET8          RRISCV = 54 // Local label subtraction
	RRISCVSET16         RRISCV = 55 // Local label subtraction
	RRISCVSET32         RRISCV = 56 // Local label subtraction
	RRISCV32_PCREL      RRISCV = 57 // 32-bit PC relative
)

// Relocation types for s390x processors.
type R390 int

const (
	R390None        R390 = 0  // None
	R3908           R390 = 1  // 8
	R39012          R390 = 2  // 12
	R39016          R390 = 3  // 16
	R39032          R390 = 4  // 32
	R390PC32        R390 = 5  // PC32
	R390GOT12       R390 = 6  // GOT12
	R390GOT32       R390 = 7  // GOT32
	R390PLT32       R390 = 8  // PLT32
	R390COPY        R390 = 9  // COPY
	R390GLOB_DAT    R390 = 10 // GLOB_DAT
	R390JMP_SLOT    R390 = 11 // JMP_SLOT
	R390RELATIVE    R390 = 12 // RELATIVE
	R390GOTOFF      R390 = 13 // GOTOFF
	R390GOTPC       R390 = 14 // GOTPC
	R390GOT16       R390 = 15 // GOT16
	R390PC16        R390 = 16 // PC16
	R390PC16DBL     R390 = 17 // PC16DBL
	R390PLT16DBL    R390 = 18 // PLT16DBL
	R390PC32DBL     R390 = 19 // PC32DBL
	R390PLT32DBL    R390 = 20 // PLT32DBL
	R390GOTPCDBL    R390 = 21 // GOTPCDBL
	R39064          R390 = 22 // 64
	R390PC64        R390 = 23 // PC64
	R390GOT64       R390 = 24 // GOT64
	R390PLT64       R390 = 25 // PLT64
	R390GOTENT      R390 = 26 // GOTENT
	R390GOTOFF16    R390 = 27 // GOTOFF16
	R390GOTOFF64    R390 = 28 // GOTOFF64
	R390GOTPLT12    R390 = 29 // GOTPLT12
	R390GOTPLT16    R390 = 30 // GOTPLT16
	R390GOTPLT32    R390 = 31 // GOTPLT32
	R390GOTPLT64    R390 = 32 // GOTPLT64
	R390GOTPLTENT   R390 = 33 // GOTPLTENT
	R390GOTPLTOFF16 R390 = 34 // GOTPLTOFF16
	R390GOTPLTOFF32 R390 = 35 // GOTPLTOFF32
	R390GOTPLTOFF64 R390 = 36 // GOTPLTOFF64
	R390TLS_LOAD    R390 = 37 // TLS_LOAD
	R390TLS_GDCALL  R390 = 38 // TLS_GDCALL
	R390TLS_LDCALL  R390 = 39 // TLS_LDCALL
	R390TLS_GD32    R390 = 40 // TLS_GD32
	R390TLS_GD64    R390 = 41 // TLS_GD64
	R390TLS_GOTIE12 R390 = 42 // TLS_GOTIE12
	R390TLS_GOTIE32 R390 = 43 // TLS_GOTIE32
	R390TLS_GOTIE64 R390 = 44 // TLS_GOTIE64
	R390TLS_LDM32   R390 = 45 // TLS_LDM32
	R390TLS_LDM64   R390 = 46 // TLS_LDM64
	R390TLS_IE32    R390 = 47 // TLS_IE32
	R390TLS_IE64    R390 = 48 // TLS_IE64
	R390TLS_IEENT   R390 = 49 // TLS_IEENT
	R390TLS_LE32    R390 = 50 // TLS_LE32
	R390TLS_LE64    R390 = 51 // TLS_LE64
	R390TLS_LDO32   R390 = 52 // TLS_LDO32
	R390TLS_LDO64   R390 = 53 // TLS_LDO64
	R390TLS_DTPMOD  R390 = 54 // TLS_DTPMOD
	R390TLS_DTPOFF  R390 = 55 // TLS_DTPOFF
	R390TLS_TPOFF   R390 = 56 // TLS_TPOFF
	R39020          R390 = 57 // 20
	R390GOT20       R390 = 58 // GOT20
	R390GOTPLT20    R390 = 59 // GOTPLT20
	R390TLS_GOTIE20 R390 = 60 // TLS_GOTIE20
)

// Relocation types for SPARC.
type RSPARC int

const (
	RSPARCNone     RSPARC = 0  // None
	RSPARC8        RSPARC = 1  // 8
	RSPARC16       RSPARC = 2  // 16
	RSPARC32       RSPARC = 3  // 32
	RSPARCDISP8    RSPARC = 4  // DISP8
	RSPARCDISP16   RSPARC = 5  // DISP16
	RSPARCDISP32   RSPARC = 6  // DISP32
	RSPARCWDISP30  RSPARC = 7  // WDISP30
	RSPARCWDISP22  RSPARC = 8  // WDISP22
	RSPARCHI22     RSPARC = 9  // HI22
	RSPARC22       RSPARC = 10 // 22
	RSPARC13       RSPARC = 11 // 13
	RSPARCLO10     RSPARC = 12 // LO10
	RSPARCGOT10    RSPARC = 13 // GOT10
	RSPARCGOT13    RSPARC = 14 // GOT13
	RSPARCGOT22    RSPARC = 15 // GOT22
	RSPARCPC10     RSPARC = 16 // PC10
	RSPARCPC22     RSPARC = 17 // PC22
	RSPARCWPLT30   RSPARC = 18 // WPLT30
	RSPARCCOPY     RSPARC = 19 // COPY
	RSPARCGLOB_DAT RSPARC = 20 // GLOB_DAT
	RSPARCJMP_SLOT RSPARC = 21 // JMP_SLOT
	RSPARCRELATIVE RSPARC = 22 // RELATIVE
	RSPARCUA32     RSPARC = 23 // UA32
	RSPARCPLT32    RSPARC = 24 // PLT32
	RSPARCHIPLT22  RSPARC = 25 // HIPLT22
	RSPARCLOPLT10  RSPARC = 26 // LOPLT10
	RSPARCPCPLT32  RSPARC = 27 // PCPLT32
	RSPARCPCPLT22  RSPARC = 28 // PCPLT22
	RSPARCPCPLT10  RSPARC = 29 // PCPLT10
	RSPARC10       RSPARC = 30 // 10
	RSPARC11       RSPARC = 31 // 11
	RSPARC64       RSPARC = 32 // 64
	RSPARCOLO10    RSPARC = 33 // OLO10
	RSPARCHH22     RSPARC = 34 // HH22
	RSPARCHM10     RSPARC = 35 // HM10
	RSPARCLM22     RSPARC = 36 // LM22
	RSPARCPC_HH22  RSPARC = 37 // PC_HH22
	RSPARCPC_HM10  RSPARC = 38 // PC_HM10
	RSPARCPC_LM22  RSPARC = 39 // PC_LM22
	RSPARCWDISP16  RSPARC = 40 // WDISP16
	RSPARCWDISP19  RSPARC = 41 // WDISP19
	RSPARCGLOB_JMP RSPARC = 42 // GLOB_JMP
	RSPARC7        RSPARC = 43 // 7
	RSPARC5        RSPARC = 44 // 5
	RSPARC6        RSPARC = 45 // 6
	RSPARCDISP64   RSPARC = 46 // DISP64
	RSPARCPLT64    RSPARC = 47 // PLT64
	RSPARCHIX22    RSPARC = 48 // HIX22
	RSPARCLOX10    RSPARC = 49 // LOX10
	RSPARCH44      RSPARC = 50 // H44
	RSPARCM44      RSPARC = 51 // M44
	RSPARCL44      RSPARC = 52 // L44
	RSPARCREGISTER RSPARC = 53 // REGISTER
	RSPARCUA64     RSPARC = 54 // UA64
	RSPARCUA16     RSPARC = 55 // UA16
)
