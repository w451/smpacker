# SMPacker Obfuscator/Anti-Signature

## Usage
smpacker.exe \[options\] \<inputfile\> \<outfile\>

## Description
* smpacker creates a "carrier" binary.
* The carrier contains two sections: .data and .text.
* The .data section contains an XORKEY struct and the input binary
* The .text section contains code to do the following:
  * Resolve required WinAPI functions
  * Decrypt the input binary
  * Check: if the last time the carrier was modified is more than 15s ago, then
    * Create new XORKEY and encrypt input binary
    * Repack the carrier (VirtualAddress->PointerToRawData)
    * Write the repacked carrier to a file
    * Use cmd to replace the carrier with the new carrier and run it
  * Else
    * Extract input binary, perform imports
    * Execute the input binary's entry point

Nesting will "work" but the innermost carrier will overwrite the nested binary with itself so it will turn back into a single carrier.
