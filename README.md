# microcode_binexport

Export IDA microcode to BinExport format so that you can use BinDiff to diff microcodes

Currently only supports mmat < MMAT_CALLS (because they won't have nested mop_t)


## Usage

run mcexport.py in IDA, and then run export.py