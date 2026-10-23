"""Disassemble per-loop snapshot.bin using capstone.

The legacy pipeline received pre-formatted assembly listings inside each
`cluster_<hash>.md`. The new PinTool only dumps raw bytes via
`PIN_SafeCopy`, so we lift those bytes back into mnemonics + operands
ourselves. Everything downstream that used to grep cluster markdown files
(loop pattern matcher, algorithm shape inference, case-study generator)
consumes the structure produced here.
"""
from __future__ import annotations

import re

try:
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
                           CS_OP_MEM)
    _HAS_CS = True
except ImportError:
    _HAS_CS = False


def _md_for(mode_bits: int):
    if not _HAS_CS:
        return None
    mode = CS_MODE_64 if mode_bits == 64 else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    return md


def detect_bitness(loop: dict, default: int = 32) -> int:
    """Spec-grounded bitness detection.

    Priority order (each step is a direct Pin measurement / PE header read,
    not inference):
      1. `bitness` field in the loop meta (PinTool may publish it directly)
      2. `image_bitness` field from the owning image (PinTool publishes per
         loaded image via PE optional-header Magic: 0x10B = PE32 / 0x20B
         = PE32+)
      3. Header IP > 0xFFFFFFFF is a positive certificate for 64-bit
         (this case is unambiguous — no 32-bit address can be that large)
      4. `default` (caller / CLI --bitness override)

    Step 3 is the only inference; it produces a true-positive for 64-bit
    but the absence of a high IP does NOT prove 32-bit (could be a 64-bit
    sample with low-VA loops). The caller is expected to pass an explicit
    `default` from the PinTool image bitness when known.  The
    function-signature default of 32 is a conservative fallback (PE32
    predominates in the corpus); callers that cannot supply image_bitness
    should log a warning."""
    # 1. Explicit bitness on the loop
    b = loop.get("bitness")
    if b in (32, 64):
        return int(b)
    # 2. Image bitness (PinTool emits via PE Magic field per Microsoft
    # PE/COFF spec section 3.4.1)
    ib = loop.get("image_bitness")
    if ib in (32, 64):
        return int(ib)
    # 3. Positive 64-bit certificate via VA range
    hdr = loop.get("header_int") or 0
    if hdr > 0xFFFFFFFF:
        return 64
    # 4. Caller default
    return default


# Capture >=2 hex-digit immediates (was >=4). The 2-3 digit masks (e.g. DES's
# 0x3f / 0x40) are needed by the des_feistel_round gate; they cannot spuriously
# match any cipher-constant needle (all crypto_constants needles are >=4 digits)
# nor any imm_const_forbidden_any needle (all 8 digits), so widening only enables
# the small-mask required-gates that ask for them.
_HEX_IMM_RE = re.compile(r"0x[0-9a-fA-F]{2,}")


def disasm_loop(loop: dict, bitness: int) -> dict:
    """Walk capstone over the snapshot bytes. Returns:
        instructions: [(address, mnemonic, op_str), ...]
        mnemonics:    [str, ...]               (lower-case, no operands)
        apis_called:  [str, ...]               (call-targets where a symbol is known)
        imm_consts:   [hex, ...]               (>=2 hex-digit immediates)
        activity:     {mem_r, mem_w, calls, calc, xor}
                                                (same shape as legacy classifier)
    """
    snap: bytes = loop.get("_snapshot_bytes") or b""
    header_int: int = loop.get("header_int") or 0
    out = {
        "instructions": [],
        "mnemonics":    [],
        "apis_called":  [],
        "imm_consts":   [],
        # rotation operands, kept apart from imm_consts: a turn by 7 or 12 is
        # a single hex digit and the immediate scanner drops those, yet the
        # amount is what names an ARX cipher's round.
        "rot_amounts":  [],
        "activity":     {"mem_r": 0, "mem_w": 0, "calls": 0,
                          "calc": 0, "xor": 0},
        "disasm_ok":    False,
        "instruction_count_disasm": 0,
        "instruction_count_meta":   loop.get("instruction_count") or 0,
    }
    if not snap or not _HAS_CS:
        return out

    md = _md_for(bitness)
    if md is None:
        return out

    activity = out["activity"]
    mnemonics: list[str] = []
    apis: list[str] = []
    imms: list[str] = []
    rots: set[int] = set()
    inst_list: list[tuple[int, str, str]] = []

    # Indirect-call enrichment via control_transfer_refs: PinTool resolved
    # `target_symbol` at runtime — capstone can't (operand is a register or
    # indirect memory). Index by instruction address.
    refs_by_addr: dict[int, dict] = {}
    for r in (loop.get("control_transfer_refs") or []):
        try:
            addr = int(r.get("address", "0"), 16)
        except (TypeError, ValueError):
            continue
        refs_by_addr[addr] = r

    # INVARIANT — `header_int` MUST be the runtime IP
    # (the VA at which `snap` was actually executing under Pin), matching
    # the addresses keyed in `refs_by_addr` (which come from PinTool's
    # runtime IPs in control_transfer_refs[].address). If `header_int` is
    # instead a file-relative offset or a default-base VA, `ins.address`
    # will not match any key in `refs_by_addr` and every indirect-call
    # symbol lookup at the `refs_by_addr.get(ins.address)` call below will
    # miss, leaving apis_called empty. Callers (loop loader / PinTool
    # parser) are responsible for populating `header_int` from the
    # observed runtime IP, NOT from `IMAGE_OPTIONAL_HEADER.ImageBase` or
    # any file offset.
    _ref_match_seen = False
    try:
        for ins in md.disasm(snap, header_int):
            mnem = ins.mnemonic.lower()
            # sanity-track refs_by_addr matches so we can
            # warn below if the invariant above is violated.
            if refs_by_addr and ins.address in refs_by_addr:
                _ref_match_seen = True
            op_str = ins.op_str
            mnemonics.append(mnem)
            inst_list.append((ins.address, mnem, op_str))

            # a rotate's own operand; rol n and ror 32-n are the same turn,
            # so both readings are recorded and a pattern need not know which
            # direction the compiler chose.
            if mnem in ("rol", "ror", "shld", "shrd"):
                tail = op_str.rsplit(",", 1)[-1].strip()
                try:
                    n = int(tail, 16) if tail.startswith("0x") else int(tail)
                except ValueError:
                    n = None
                if n is not None and 0 < n < 32:
                    rots.add(n)
                    rots.add(32 - n)

            # ── activity vector ─────────────────────────────────────────
            #
            # string ops (MOVS/STOS/LODS) have no explicit
            # operands in capstone — they implicitly use [E/RSI]/[E/RDI].
            # The original `if ins.operands:` gate skipped them entirely so
            # tight string-copy loops scored 0 mem_r/mem_w and were
            # mis-classified as compute loops. Handle them by mnemonic
            # before falling through to operand inspection.
            #
            # Also: `movsd` is ambiguous — it is both the legacy
            # string-mov-doubleword and the SSE2 scalar move-double. SSE2
            # scalar movsd *does* have operands, so we route mnem=="movsd"
            # with operands through the normal MOV path (operand-direction
            # decides mem_r vs mem_w), and operand-less movsd through the
            # string path.
            _STRING_MNEMS_W = ("stos", "stosb", "stosw", "stosd", "stosq")
            _STRING_MNEMS_R = ("lods", "lodsb", "lodsw", "lodsd", "lodsq")
            _STRING_MNEMS_RW = ("movs", "movsb", "movsw", "movsq")
            # NOTE: 'movsd' deliberately omitted from _STRING_MNEMS_RW —
            # it disambiguates by operand presence below.

            if mnem in _STRING_MNEMS_W:
                activity["mem_w"] += 1
            elif mnem in _STRING_MNEMS_R:
                activity["mem_r"] += 1
            elif mnem in _STRING_MNEMS_RW:
                activity["mem_r"] += 1
                activity["mem_w"] += 1
            elif mnem == "movsd" and not ins.operands:
                # String-MOVS doubleword: implicit [rsi]->[rdi]
                activity["mem_r"] += 1
                activity["mem_w"] += 1
            elif mnem in ("mov", "movzx", "movsx", "movsxd", "movups",
                         "movdqa", "movdqu", "movq", "movd",
                         "movsd", "movss"):
                if ins.operands:
                    # dst,src — first operand is destination
                    dst = ins.operands[0]
                    if dst.type == CS_OP_MEM:
                        activity["mem_w"] += 1
                    elif len(ins.operands) > 1 and \
                            ins.operands[1].type == CS_OP_MEM:
                        activity["mem_r"] += 1
            elif mnem == "lea":
                # lea computes an effective address; it touches no memory, so it
                # must count toward neither mem_r nor mem_w (only address arithmetic).
                activity["calc"] += 1
            elif mnem in ("xor", "pxor", "vpxor", "xorps", "xorpd"):
                activity["xor"] += 1
                # XOR is RMW when destination is memory
                # (e.g. `xor [mem],reg` in AES/RC4/ChaCha hot loops). Without
                # this, mem_r/mem_w stay 0 for cipher cores that XOR into a
                # state buffer, biasing the activity vector toward 'pure
                # compute' and risking misclassification. Mirror the MOV path
                # but treat memory-dst as both read and write (RMW).
                if ins.operands:
                    dst = ins.operands[0]
                    if dst.type == CS_OP_MEM:
                        activity["mem_w"] += 1
                        activity["mem_r"] += 1
                    elif len(ins.operands) > 1 and \
                            ins.operands[1].type == CS_OP_MEM:
                        activity["mem_r"] += 1
            # extend calc mnemonics to cover AND/OR/NOT,
            # CMP/TEST, BSWAP, XCHG, and SIMD arithmetic. AES MixColumns and
            # SHA-2 majority/choice rely heavily on AND/OR; the previous list
            # missed them entirely, undercounting calc activity. SIMD
            # paddd/pand/por/vpand/vpor are also genuine compute.
            elif mnem in ("add", "sub", "imul", "mul", "div", "idiv",
                           "inc", "dec", "neg", "shl", "shr", "sar",
                           "rol", "ror", "rcl", "rcr",
                           "and", "or", "not", "cmp", "test",
                           "bswap", "xchg",
                           "paddd", "paddq", "paddw", "paddb",
                           "psubd", "psubq", "psubw", "psubb",
                           "pmuludq", "pmulld", "pmullw",
                           "pand", "por", "pandn",
                           "vpand", "vpor", "vpandn",
                           "vpaddd", "vpaddq", "vpsubd", "vpsubq"):
                activity["calc"] += 1
                # arithmetic mnemonics on memory operands
                # (e.g. `add [mem],reg`, `and [mem],imm`) read and write
                # memory. Without this, RMW arithmetic on a state buffer is
                # silently dropped from mem_r/mem_w. CMP/TEST are read-only;
                # everything else here is RMW when dst is memory.
                if ins.operands:
                    dst = ins.operands[0]
                    if dst.type == CS_OP_MEM:
                        activity["mem_r"] += 1
                        if mnem not in ("cmp", "test"):
                            activity["mem_w"] += 1
                    elif len(ins.operands) > 1 and \
                            ins.operands[1].type == CS_OP_MEM:
                        activity["mem_r"] += 1
            elif mnem == "call":
                activity["calls"] += 1
                ref = refs_by_addr.get(ins.address)
                if ref and ref.get("target_symbol"):
                    sym = ref["target_symbol"]
                    if sym and sym not in apis:
                        apis.append(sym)

            for h in _HEX_IMM_RE.findall(op_str):
                imms.append(h.lower())

        out["disasm_ok"] = True
        # emit a one-shot warning when refs_by_addr is
        # populated but no disassembled instruction address ever matched a
        # ref key. This is a strong signal that `header_int` was passed as a
        # file-relative offset rather than the runtime IP, which silently
        # zeros out indirect-call symbol resolution (apis_called stays
        # empty). Logged to stderr to keep the function dependency-free.
        if refs_by_addr and not _ref_match_seen:
            import sys
            print(
                "[disasm] WARNING: %d control_transfer_refs present but no "
                "disassembled address matched any ref key. Check that "
                "loop['header_int'] is the runtime IP (got 0x%x), not a "
                "file offset or ImageBase-relative RVA."
                % (len(refs_by_addr), header_int),
                file=sys.stderr,
            )
    except Exception:
        # capstone raised — keep partial results
        pass

    out["instructions"]            = inst_list
    out["mnemonics"]               = mnemonics
    out["apis_called"]             = apis
    out["imm_consts"]              = imms
    out["rot_amounts"] = sorted(rots)
    out["instruction_count_disasm"] = len(inst_list)
    return out


def render_listing(loop: dict, max_lines: int = 32) -> str:
    """One-line-per-insn ASCII listing for the case-study Markdown."""
    insts = (loop.get("_disasm") or {}).get("instructions") or []
    lines = []
    for addr, mnem, op in insts[:max_lines]:
        lines.append(f"  0x{addr:08x}  {mnem:<7s} {op}")
    if len(insts) > max_lines:
        lines.append(f"  ... ({len(insts) - max_lines} more)")
    return "\n".join(lines)
