package xdwarf

// Standard line number program opcodes (DWARF 5 section 6.2.5.2).
type LineOp uint8

const (
	LineOpCopy           LineOp = 0x01 // DW_LNS_copy
	LineOpAdvancePC      LineOp = 0x02 // DW_LNS_advance_pc
	LineOpAdvanceLine    LineOp = 0x03 // DW_LNS_advance_line
	LineOpSetFile        LineOp = 0x04 // DW_LNS_set_file
	LineOpSetColumn      LineOp = 0x05 // DW_LNS_set_column
	LineOpNegateStmt     LineOp = 0x06 // DW_LNS_negate_stmt
	LineOpSetBasicBlock  LineOp = 0x07 // DW_LNS_set_basic_block
	LineOpConstAddPC     LineOp = 0x08 // DW_LNS_const_add_pc
	LineOpFixedAdvancePC LineOp = 0x09 // DW_LNS_fixed_advance_pc
	LineOpSetPrologueEnd LineOp = 0x0a // DW_LNS_set_prologue_end
	LineOpSetEpilogueBeg LineOp = 0x0b // DW_LNS_set_epilogue_begin
	LineOpSetISA         LineOp = 0x0c // DW_LNS_set_isa
)

// Extended line number program opcodes, introduced by a zero opcode byte.
type LineExtOp uint8

const (
	LineExtEndSequence  LineExtOp = 0x01 // DW_LNE_end_sequence
	LineExtSetAddress   LineExtOp = 0x02 // DW_LNE_set_address
	LineExtDefineFile   LineExtOp = 0x03 // DW_LNE_define_file, DWARF 2-4 only.
	LineExtSetDiscrimin LineExtOp = 0x04 // DW_LNE_set_discriminator
)

// Line header entry content type codes, DWARF 5 section 6.2.4.1. They describe
// what each column of the directory and file tables holds.
type LineContent uint64

const (
	LineContentPath      LineContent = 0x1 // DW_LNCT_path
	LineContentDirIndex  LineContent = 0x2 // DW_LNCT_directory_index
	LineContentTimestamp LineContent = 0x3 // DW_LNCT_timestamp
	LineContentSize      LineContent = 0x4 // DW_LNCT_size
	LineContentMD5       LineContent = 0x5 // DW_LNCT_MD5
)

// Attribute forms. Only the forms that can appear in a line program header's
// directory and file tables are listed; everything else is rejected rather than
// skipped, since an unexpected form means the table cannot be trusted.
type Form uint64

const (
	FormBlock2   Form = 0x03 // DW_FORM_block2
	FormBlock4   Form = 0x04 // DW_FORM_block4
	FormData2    Form = 0x05 // DW_FORM_data2
	FormData4    Form = 0x06 // DW_FORM_data4
	FormData8    Form = 0x07 // DW_FORM_data8
	FormString   Form = 0x08 // DW_FORM_string
	FormBlock    Form = 0x09 // DW_FORM_block
	FormBlock1   Form = 0x0a // DW_FORM_block1
	FormData1    Form = 0x0b // DW_FORM_data1
	FormFlag     Form = 0x0c // DW_FORM_flag
	FormSdata    Form = 0x0d // DW_FORM_sdata
	FormStrp     Form = 0x0e // DW_FORM_strp
	FormUdata    Form = 0x0f // DW_FORM_udata
	FormData16   Form = 0x1e // DW_FORM_data16
	FormLineStrp Form = 0x1f // DW_FORM_line_strp
)
