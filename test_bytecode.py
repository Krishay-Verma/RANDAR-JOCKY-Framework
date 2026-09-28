"""
Milestone 5 test — IR/Bytecode pipeline.
"""

import base64
from jocky.language.lexer import tokenize
from jocky.language.parser import parse
from jocky.language.bytecode import (
    compile_investigation,
    verify_and_load,
    disassemble,
    BytecodeError,
)
from jocky.language.interpreter import run_investigation

SCRIPT = """
investigation "Bytecode Triage" {
    let threshold = 10;

    collect system_info;
    collect processes;

    if processes.count > threshold {
        collect network_connections;
        analyze process_network_correlation;
    } else {
        analyze missing_paths;
    }

    analyze suspicious_processes;
    report "bytecode_triage";
}
"""


def main() -> None:
    print("=== JOCKY Milestone 5 — Bytecode Pipeline ===\n")

    # 1. Compile
    print("1. Compiling to bytecode...")
    tokens = tokenize(SCRIPT)
    investigation = parse(tokens)
    blob = compile_investigation(investigation)
    b64 = base64.b64encode(blob).decode("ascii")
    print(f"   Bytecode size : {len(blob)} bytes")
    print(f"   Base64 length : {len(b64)} chars")

    # 2. Verify
    print("\n2. Verifying signature...")
    header, opcodes = verify_and_load(blob)
    print(f"   Magic         : {header['magic']}")
    print(f"   Version       : {header['version']}")
    print(f"   Name          : {header['name']}")
    print(f"   Compiled at   : {header['compiled_at']}")
    print(f"   Opcode count  : {len(opcodes)}")
    print(f"   Signature     : OK")

    # 3. Disassemble
    print("\n3. Disassembly:")
    listing = disassemble(blob)
    for line in listing.split("\n"):
        print(f"   {line}")

    # 4. Tamper detection
    print("\n4. Tamper detection test...")
    tampered = bytearray(blob)
    tampered[20] ^= 0xFF   # flip a byte in the header
    try:
        verify_and_load(bytes(tampered))
        print("   FAIL — tampered bytecode was not detected!")
    except BytecodeError:
        print("   PASS — tampered bytecode correctly rejected.")

    # 5. Execute from bytecode
    print("\n5. Executing from bytecode...")
    from jocky.api.bytecode_routes import _opcodes_to_ir
    reconstructed = _opcodes_to_ir(header["name"], opcodes)
    result = run_investigation(reconstructed)
    print(f"   Collectors run : {len(result.collector_results)}")
    for cr in result.collector_results:
        print(f"     [{cr.status}] {cr.target}")
    print(f"   Findings       : {len(result.findings)}")

    print("\n=== Done ===")


if __name__ == "__main__":
    main()