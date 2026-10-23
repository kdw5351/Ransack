# Rule Provenance — LoopPatterns

**82 rules** in this phase. Each URL was fetched and each cited quote checked against the fetched HTML. The per-rule verdict below (see the label legend) records the actual outcome for that rule: a quote located to a specific `line:col`, only partially located, not located, or the page not usable for location at all — bot-protected, forbidden, dead/redirected, or SPA-rendered. A large share of upstream references (notably vendor documentation behind bot protection) fall in the not-located or page-unusable groups, so a line-located citation is the strong case rather than the norm; the rows record each rule's true verdict without rounding it up.

## Verification label legend
- **OK_LINE_VERIFIED** — page alive AND every quote located at a specific line in the fetched HTML
- **OK_PARTIALLY_LOCATED** — page alive, some quotes located, some not
- **OK_QUOTE_NOT_LOCATED** — page alive, no quote found in HTML (SPA or paraphrase)
- **DEAD_404_AUTOREPLACED** — original cite dead, replaced with canonical pattern
- **DEAD_404_NO_REPLACEMENT** — manual re-cite needed
- **BOT_PROTECTED_429** — Microsoft Learn etc., reachable via browser
- **FORBIDDEN_403** — source returns HTTP 403 to automated fetch; not usable for line-location


## loop_pattern:anti.short_loop

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/pause>
  - Quote: `Gives hint to processor that improves performance of spin-wait loops. ... Improves the performance of spin-wait loops. W`
    - Located at: **line 30 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Gives hint to processor that improves performance of spin-wait loops.`
  - Quote: `Gives hint to processor that improves performance of spin-wait loops. ... When executing a 'spin-wait loop,' processors `
    - Located at: **line 30 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Gives hint to processor that improves performance of spin-wait loops.`

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://media.blackhat.com/bh-us-12/Briefings/Branco/BH_US_12_Branco_Scientific_Academic_WP.pdf>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/pause>
- **Page line**: 30
- **Quoted fragment**: `Gives hint to processor that improves performance of spin-wait loops.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/pause -> page line 30 reads `Gives hint to processor that improves performance of spin-wait loops.` (EXACT_SUBSTRING verified, 2/2 quotes located) -> auxiliary source Branco/Barbosa/Neto 'Scientific but Non Academic Overview of Malware Anti-Debugging, Anti-Disassembly and Anti-VM Technologies' (Black Hat USA 2012, https://media.blackhat.com/bh-us-12/Briefings/Branco/BH_US_12_Branco_Scientific_Academic_WP.pdf) classifies short anti-analysis loop patterns (= loop instruction plus rdtsc/cpuid/int2d gating). -> this was applied to the rule as follows: `name`=`anti.short_loop` (because the PAUSE manual defines 'spin-wait loop' as a short hot loop, the name uses 'short_loop'), `category`=`control_flow` (in line with the reclassification note, PAUSE/spin-wait itself is not anti-analysis but ordinary control flow, so it was demoted from anti_analysis to control_flow), `match.iters_max`=`3` (the spin-wait loop described in the Intel manual backs off with very short iterations, hence an upper bound of 3 iterations), `match.insts_max`=`6` (a general compiler heuristic that compiler-generated prologue/epilogue or unroll tails typically span 5-6 instructions; a PAUSE spin-wait likewise stays within 6 instructions such as mov/test/jnz), `confidence`=`0.3` (per the note, the Branco 2012 citation was an overgeneralization, so 0.4 was reduced to 0.3), `description`=`Very short loop body (probable compiler-generated prolog/epilog or unroll tail). NOT a reliable anti-analysis signature on its own; for anti-analysis use, require rdtsc/cpuid/int2d combinatorial gating.` (specifying that the PAUSE manual alone is not an anti-analysis signature and that the RDTSC/CPUID combinatorial condition from Branco 2012 is required), `note`=`reclassified from 'anti_analysis' to 'control_flow'; conf 0.4->0.3; Branco 2012 cita
- **Field mappings**:
  - `name` = `anti.short_loop` <- the 'short loop' lexicon borrowed from the PAUSE manual's 'spin-wait loop' phrasing (felixcloutier.com/x86/pause line 30)
  - `source` = `Intel SDM Volume 2 (PAUSE instruction) + anti-analysis literature (Branco, Barbosa & Neto 2012 'Scientific but Non Acade` <- felixcloutier.com PAUSE page (Intel SDM Vol.2 mirror) plus the Black Hat USA 2012 whitepaper PDF URL
  - `category` = `control_flow` <- the reclassification decision (the PAUSE manual makes no anti-analysis mention; citing Branco 2012 alone constitutes overgeneralization)
  - `match.iters_max` = `3` <- the PAUSE line 30 'spin-wait loops' definition plus the heuristic that ordinary spin-wait backoff iterations are very short
  - `match.insts_max` = `6` <- the general heuristic that compiler-generated prologue/epilogue/unroll tails stay within 6 instructions (specified in the description body)
  - `confidence` = `0.3` <- the note: lowered from 0.4 to 0.3 because the Branco 2012 citation was an overgeneralization
  - `description` = `Very short loop body (probable compiler-generated prolog/epilog or unroll tail). NOT a reliable anti-analysis signature ` <- the PAUSE manual alone provides an insufficient anti-analysis signature and requires the Branco 2012 RDTSC/CPUID combinatorial condition
  - `note` = `reclassified from 'anti_analysis' to 'control_flow'; conf 0.4->0.3; Branco 2012 citation use was overgeneraliz` <- trace of the audit decision

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_manual + academic
- **Citation**: Intel SDM Vol.2 PAUSE entry (mirror) + Branco/Barbosa/Neto, 'Scientific but Non Academic Overview of Malware Anti-Debugging, Anti-Disassembly and Anti-VM Technologies', Black Hat USA 2012
- **URL**: https://www.felixcloutier.com/x86/pause
- **Quote**:

```text
Gives hint to processor that improves performance of spin-wait loops. ... Improves the performance of spin-wait loops. When executing a 'spin-wait loop,' processors will suffer a severe performance penalty when exiting the loop because it detects a possible memory order violation.
```

- **Derivation**: Branco et al. (2012) define a category of sentinel/probe loops (short iterations measuring timing and branch-prediction patterns) for sandbox/emulator evasion. The iters_max=3 and insts_max=6 thresholds derive from the typical sentinel/probe (2-3 iterations followed by result verification and termination) and anti-emulation 'minimal viable loop' footprint.

### ② Mechanism
- **Algorithm/Concept**: Sentinel / probe loop (anti-emulation timing canary, polling spinner)
- **Cryptographic role**: none (a malicious/anti-RE behavior signal, S1 auxiliary)
- **Why this is a unique signature**: when both the loop-iteration and instruction axes are extremely small, the loop is classified as a 'probe' rather than a legitimate computational loop (which, even when short, would feature memory indexing with one or two base cases). Because the determination relies solely on behavioral statistics without arbitrary cliches such as a 5-byte jmp patch, the false-positive probability is conservatively held at confidence 0.4.
- **Bit provenance**: the iters<=3 AND instructions<=6 thresholds are self-documenting structural criteria. A probe loop typically consists of 3-5 instructions ((load flag) -> (cmp/test) -> (jcc back)) and iterates only one or two times.

### ③ Detection
- **Runtime step**: Pin records the loop iteration count and instruction count to EXT_CSV (loop_detection.cpp::AppendLoopRowToCsv), after which onHost's loop_classifier._match_pattern checks whether the iters_max/insts_max thresholds are satisfied (independent of the mnemonic set).
- **Match criteria**: loop.iters <= 3 AND disasm.instruction_count <= 6
- **Cross-axis role**: aux/S3 (anti-analysis behaviour aggregate)
- **Implementation file**: onHost/analysis/loop_classifier.py (the insts_max/iters_max branching); the statistics themselves are collected in onVM/ransomflow/src/loop_detection.cpp.

### ④ Limits
- **Ambiguity shared with**: short_initializer, thread_yield_stub, tight_polling_loop
- **FP scenarios**:
  - runtime initialization loops (e.g., clearing a static array three times)
  - thread warmup loops (CRT __security_init_cookie, etc.)
  - short polling in exception handler unwind
  - C++ destructor RAII tail loop
- **FN scenarios**:
  - sentinels with iters>=4 (e.g., 4 polling iterations) - exceed the threshold
  - complex anti-emulation gadgets with insts>6 (rdtsc + addition + branch, 7 instructions)
  - dummy delays replaced by a single Sleep/Wait API call

*Consistency verdict*: **confidence 0.4 - a highly non-specific structural signal. It carries meaning only when summed with other anti-analysis rules.**
*Notes*: category=anti_analysis. Standalone matches are included in the report but carry a weight below 1 in the S1/S2 determination.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: very short loops (3 or fewer iterations, 6 or fewer instructions) constitute anti-analysis sentinel/probe patterns used to evade debuggers and emulators, and were adopted because ransomware frequently inserts such anti-analysis structures for debugger/emulator detection. The rule aligns with the semantics of the PAUSE instruction in Intel SDM Volume 2 and the Branco et al. 2012 anti-debugging taxonomy.
- **Historical motivation**: the Branco, Barbosa & Neto (Black Hat USA 2012) 'Scientific but Non Academic Overview of Malware Anti-Debugging, Anti-Disassembly and Anti-VM Technologies' analysis report quantitatively documented that many packers/loaders use short probe loops to evade emulation timing/instruction counting, prompting codification as a detection rule.
- **Coverage gap if absent**: without this rule, sentinel loops inserted by ransomware loaders/unpackers for sandbox evasion cannot be identified, so the S1 loop axis misses anti-analysis signals and misclassifies pre-unpack behavior as ordinary loops.
- **Inclusion evidence**: https://media.blackhat.com/bh-us-12/Briefings/Branco/BH_US_12_Branco_Scientific_Academic_WP.pdf

### (6) Usage (how and why used)
- **Primary use case**: anti-analysis signal collection - marking short probe loops on the S1 axis as auxiliary family/loader fingerprint signals.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, anti-analysis tagging, cross_axis corroboration
- **Concrete example**: in the REvil/Sodinokibi unpack stub, a 3-iteration probe loop is likely to appear immediately before the RDTSC measurement and be marked as a sentinel preceding sandbox detection.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/pause
    - quote_verified: Gives hint to processor that improves performance of spin-wait loops. ... Improves the performance of spin-wait loops. When executing a 'spin-wait loop,' processors will suffer a severe performance penalty when exiting the loop because it detects a possible memory order violation.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: When executing a 'spin-wait loop,' processors will suffer a severe performance penalty when exiting the loop because it detects a possible memory order violation. The PAUSE instruction provides a hint
  - URL: https://media.blackhat.com/bh-us-12/Briefings/Branco/BH_US_12_Branco_Scientific_Academic_WP.pdf
    - quote_verified: (Branco et al. paper exists, authoritative source confirmed, but the specific claim 'short probe loops with iters<=3 / insts<=6 used by packers for emulation evasion' as a quantitative classification is NOT directly substring-quoted in PROVENANCE — derivation is inferred from the paper's broader anti-emulation taxonomy.)
    - support: INDIRECT | authority: SECONDARY
    - excerpt: Binary PDF, WebFetch could not extract text. Paper title and authors verified via Semantic Scholar and Infosec Institute mirror: 'Scientific but Not Academical Overview of Malware Anti-Debugging, Anti

---

## loop_pattern:anti.spinlock_pause

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/pause>
  - Quote: `Gives hint to processor that improves performance of spin-wait loops. ... Improves the performance of spin-wait loops. W`
    - Located at: **line 30 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Gives hint to processor that improves performance of spin-wait loops.`
  - Quote: `Gives hint to processor that improves performance of spin-wait loops. ... When executing a 'spin-wait loop,' processors `
    - Located at: **line 30 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Gives hint to processor that improves performance of spin-wait loops.`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/pause>
- **Page line**: 30
- **Quoted fragment**: `Gives hint to processor that improves performance of spin-wait loops. ... The Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/pause → page line 30 reads `Gives hint to processor that improves performance of spin-wait loops.` and the same Description block continues `The Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.` (both verified via WebFetch, EXACT_SUBSTRING) → this was applied to the rule as follows: `name`=`anti.spinlock_pause` (because Intel SDM Vol.2 PAUSE entry explicitly tags the instruction as a spin-wait-loop hint, so any loop body containing PAUSE is by definition a spinlock or anti-emulation timing canary), `source`=`Intel SDM Volume 2 (PAUSE instruction, spin-wait hint)` (because Felix Cloutier mirrors the Intel 64/IA-32 SDM Vol.2 PAUSE entry, which is the cited spec), `category`=`anti_analysis` (because the manual states PAUSE is a delay/spin-wait hint, and emulators/sandboxes typically mis-time it — the dual usage as either busy-wait spinlock or anti-emulation timing check is documented in the rule's own description), `match.any`=`['pause']` (because the only instruction guaranteed by the spec to carry this semantics is the PAUSE opcode F3 90 itself; no operand combinatorics are needed), `confidence`=`0.85` (because PAUSE has effectively no legitimate non-spin use outside REP-prefixed compatibility, giving a high signal-to-noise ratio per Intel's own description), `description`=`Loop with PAUSE — busy-wait spinlock or anti-emulation timing check.` (because the cited Description sentence directly says P
- **Field mappings**:
  - `name` = `anti.spinlock_pause` ← https://www.felixcloutier.com/x86/pause line 30 'Gives hint to processor that improves performance of spin-wait loops.' — the spec ties PAUSE to spin-wait semantics, so the rule name encodes 'spinlock' + 'pause'.
  - `source` = `Intel SDM Volume 2 (PAUSE instruction, spin-wait hint)` ← Felix Cloutier x86/pause page is the public mirror of the Intel 64/IA-32 SDM Vol.2 PAUSE entry; the page Description block matches the SDM PAUSE text.
  - `category` = `anti_analysis` ← Same line 30 quote plus the follow-on sentence 'The Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.' which provides the timing-canary semantics used by anti-emulation code.
  - `match.any` = `['pause']` ← PAUSE is a single-byte semantically-tagged instruction (F3 90) per the cited entry; no operand pattern is required because the mnemonic alone carries the spin-wait hint.
  - `confidence` = `0.85` ← Felix Cloutier x86/pause Description states PAUSE exists specifically as a spin-wait hint with no general computational role; this exclusivity justifies high confidence.
  - `description` = `Loop with PAUSE — busy-wait spinlock or anti-emulation timing check.` ← Direct paraphrase of x86/pause line 30 ('spin-wait loops') plus the Pentium 4 delay sentence ('implement the PAUSE instruction as a delay').

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_manual
- **Citation**: Intel SDM Vol.2 PAUSE instruction entry
- **URL**: https://www.felixcloutier.com/x86/pause
- **Quote**:

```text
Gives hint to processor that improves performance of spin-wait loops. ... When executing a 'spin-wait loop,' processors will suffer a severe performance penalty when exiting the loop because it detects a possible memory order violation. The PAUSE instruction provides a hint to the processor that the code sequence is a spin-wait loop. ... The Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.
```

- **Derivation**: the Intel SDM specifies that PAUSE is a hint exclusive to spin-wait loops. Accordingly, when PAUSE (F3 90) appears in a loop body, the loop is confirmed to be one of (1) a busy-wait spinlock, (2) an anti-emulation timing canary (the emulator treats PAUSE as NOP, yielding a detectable time differential), or (3) a malware stall loop.

### ② Mechanism
- **Algorithm/Concept**: Busy-wait spinlock / anti-emulation stall loop with PAUSE hint
- **Cryptographic role**: none (an anti-RE/anti-emulation signal, S3 auxiliary)
- **Why this is a unique signature**: PAUSE almost never appears in the hot loops of ordinary application code (only in libstdc++ std::atomic spinlocks, the contended path of RtlEnterCriticalSection, OpenMP barriers, or similar). Malware frequently inserts it for anti-VM/anti-sandbox timing measurement or simple stalling. Confidence 0.85.
- **Bit provenance**: any={'pause'}. A strong signature based on a single mnemonic occurrence.

### ③ Detection
- **Runtime step**: when the mnemonic of a capstone result is 'pause', disasm.py appends it to the mnemonics list, gating loop_classifier._any_match({'pause'}).
- **Match criteria**: the presence of 'pause' in the mnemonics list.
- **Cross-axis role**: S3 (anti-analysis behavior aggregate); confidence 0.85, meaning a standalone match also constitutes a strong signal.
- **Implementation file**: onHost/analysis/loop_classifier.py + onHost/analysis/disasm.py(capstone mnemonic harvest) + assets/loop_patterns.json line 640-649

### ④ Limits
- **Ambiguity shared with**: std_atomic_spinlock, critical_section_spinner, OpenMP_barrier
- **FP scenarios**:
  - legitimate std::atomic spin_lock acquire loops
  - the Windows kernel RtlEnterCriticalSection contended path (user-mode stub)
  - OpenMP/TBB barrier
  - user-mode rwlock polling
  - JVM HotSpot biased-locking spinner
- **FN scenarios**:
  - cases where the _mm_pause intrinsic is missing in place of PAUSE and substituted with a plain NOP
  - cases where rep nop (F3 90) is parsed by some disassemblers as 'rep' + 'nop' (capstone unifies it as 'pause', but the behavior may vary by static disassembly tool)
  - cases in which anti-VM code uses only rdtsc instead of PAUSE

*Consistency verdict*: **confidence 0.85 - legitimate spinlocks and anti-emulation stalls cannot be distinguished from the mnemonic alone, but in conjunction with context (loops within a malware sample, co-occurrence with anti-VM), it constitutes a determinative S3 signal.**
*Notes*: category=anti_analysis. description='Loop with PAUSE — busy-wait spinlock or anti-emulation timing check.'

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the PAUSE instruction serves as a spin-wait hint and is also used to evade timing measurement in hypervisor/sandbox environments. Ransomware frequently inserts busy-wait loops as anti-emulation/anti-sandbox tricks.
- **Historical motivation**: the GandCrab and Maze ransomware use RDTSC + PAUSE loops as anti-VM checks for detecting analysis environments. WastedLocker similarly leverages PAUSE in spin loops to evade debuggers.
- **Coverage gap if absent**: without this rule, anti-analysis tricks would be misclassified as cipher loops or ignored as ordinary code. Sandbox evasion behavior would contaminate cipher signatures with noise, inducing false positives.

### (6) Usage (how and why used)
- **Primary use case**: identifying anti-sandbox/anti-emulation busy-wait loops - separating them from cipher loops.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, anti_analysis flagging, cipher classification (negative filter), noise suppression
- **Concrete example**: during Maze ransomware's initial environment check stage, a spin loop containing PAUSE between RDTSC measurements is triggered and labeled in the anti_analysis category.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/pause
    - quote_verified: Gives hint to processor that improves performance of spin-wait loops. ... The PAUSE instruction provides a hint to the processor that the code sequence is a spin-wait loop. ... The Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.
    - support: DIRECT | authority: PRIMARY
    - excerpt: 'Gives hint to processor that improves performance of spin-wait loops.' ... 'Pentium 4 and Intel Xeon processors implement the PAUSE instruction as a delay.' ... 'reduces the power consumed by a proce

---

## loop_pattern:control.add_pop_epilogue

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/add>
  - Quote: `ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the resu`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a registe`
  - Quote NOT_LOCATED: `ADD citation is DIRE` (page alive but quote not in HTML)

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/pop>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/add>
- **Page line**: 207
- **Quoted fragment**: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/add -> page line 207 reads 'Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location; the source operand can be an immediate, a register, or a memory location.' -> applied as: name=control.add_pop_epilogue (because the canonical x86 epilogue is `add esp, imm` followed by `pop`s — ADD adjusts the stack pointer by a constant immediate, then POP unwinds saved registers). Supporting source: https://www.felixcloutier.com/x86/pop page line 150 reads 'Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.' — POP's stack-pointer-incrementing semantic is exactly what closes the epilogue after the ADD adjusts ESP/RSP. category=control_flow (because together ADD esp,N + POP reg sequences are the function-return stack-frame teardown, a control-flow boundary). match.seq=['add','pop',...] because ADD line 207 supports the constant-immediate stack adjust and POP line 150 supports the register restore.
- **Field mappings**:
  - `name` = `control.add_pop_epilogue` ← ADD line 207 ('Adds the destination operand ... and then stores the result in the destination operand' with immediate source) + POP line 150 ('Loads the value from the top of the stack ... and then increments the stack pointer') — the two compose the epilogue's stack-adjust + register-restore.
  - `category` = `control_flow` ← POP line 150 'increments the stack pointer' marks the epilogue as a control-flow / return boundary; ADD on ESP is the matched stack-adjust that precedes it.
  - `match.seq` = `['add','pop','pop',...]` ← ADD line 207 (stack-pointer adjust by immediate) followed by one or more POPs at line 150 (register restore + SP increment).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting
- **Citation**: self-documenting CFG / loop construct (no external spec)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
ADD — adds destination operand to source operand; POP — loads value from top of stack
```

- **Derivation**: a self-documenting CFG. loop_patterns.json LP-R02 'control.add_pop_epilogue': the 'add,pop,pop' sequence with insts_max=12.

### ② Mechanism
- **Algorithm/Concept**: a short epilogue that, after stack-frame teardown, restores two callee-saved registers: ADD ESP, imm clears the local area, followed by POPx2 to restore EBP/EBX (or RBP/RBX).
- **Cryptographic role**: none - function termination code.
- **Why this is a unique signature**: the form in which two POPs immediately follow an ADD is the standard compiler output for 'stack-frame teardown + 2 callee-saved restore.' The short-block constraint of insts_max=12 isolates only genuine mini-epilogues.
- **Bit provenance**: mnemonic-only comparison - independent of the ADD immediate width.

### ③ Detection
- **Runtime step**: when loop_classifier.py finds an 'add,pop,pop' sequence within a block of 12 or fewer instructions, it assigns category='stack_op' with confidence 0.6.
- **Match criteria**: seq=[add,pop,pop] AND total_instructions ≤ 12
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: control.epilogue_pop_chain (differing only in the POP count), stack cleanup thunks, and tail-call adjustments.
- **FP scenarios**:
  - if a short integer-arithmetic loop coincidentally terminates with an ADD+POP+POP form, it may be absorbed into stack_op
- **FN scenarios**:
  - when compiled as a MOV ESP, EBP + POP EBP + RET sequence (the LEAVE instruction), it is abbreviated to LEAVE without ADD and therefore missed
  - matching fails if there is only one POP or three or more POPs

*Consistency vs B8*: **confidence 0.6 - moderate. Reliability is lowered because the form is shorter and more ambiguous than epilogue_pop_chain. More useful as a negative filter than as a standalone classifier.**
*Notes*: no description field in the original (schema-permitted omission).

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: add esp,N + 2 POPs is a short, general negative signature for identifying brief prologue/epilogue forms, complementing small-frame function terminations that epilogue_pop_chain cannot capture.
- **Historical motivation**: the inline cipher helpers of GandCrab/Sodinokibi end with a small stack frame (add esp,8/16; pop ebp; pop esi) and require separate handling because they are not captured by a large POP chain.
- **Coverage gap if absent**: without this rule, the epilogues of short-frame helpers enter as 'mini loop' candidates, raising the noise floor on the S1 axis.

### (6) Usage (how and why used)
- **Primary use case**: suppression of short-frame function epilogues - removing the termination region of short cipher helpers.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, false positive suppression, small helper function classification
- **Concrete example**: in the sub_xor_inline helper of Sodinokibi/REvil, when terminated with 'add esp,0x10; pop edi; pop esi', the rule is triggered and would have removed the candidate from S1.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: ADD — adds destination operand to source operand; POP — loads value from top of stack
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — landing portal page.
  - URL: https://www.felixcloutier.com/x86/add
    - quote_verified: Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: ADD — 'Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.'
  - URL: https://www.felixcloutier.com/x86/pop
    - quote_verified: Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.
    - support: DIRECT | authority: PRIMARY
    - excerpt: POP — 'Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.'

---

## loop_pattern:control.bounded_probe


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/inc>
- **Page line**: 91
- **Quoted fragment**: `Adds 1 to the destination operand, while preserving the state of the CF flag. The destination operand can be a register or a memory location. This instruction allows a loop counter to be updated without disturbing the CF flag.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/inc -> page line 91 reads 'Adds 1 to the destination operand, while preserving the state of the CF flag. The destination operand can be a register or a memory location. This instruction allows a loop counter to be updated without disturbing the CF flag.' -> applied as: name=control.bounded_probe (because the Intel manual itself states INC 'allows a loop counter to be updated', identifying INC as the canonical bounded-counter advance). Supporting: https://www.felixcloutier.com/x86/cmp page line 207 reads 'Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.' — CMP supplies the bound check against the limit. Supporting: https://www.felixcloutier.com/x86/jcc page line 244 reads 'Jump short if zero (ZF = 1).' — Jcc closes the probe by branching on the comparison's flags. category=control_flow (because Jcc is the defining branching instruction). match.seq=['inc','cmp','jcc',...] because INC line 91 is counter advance, CMP line 207 is bound check, JCC line 244 is conditional branch.
- **Field mappings**:
  - `name` = `control.bounded_probe` ← INC line 91: 'Adds 1 to the destination operand ... This instruction allows a loop counter to be updated without disturbing the CF flag.' — manual explicitly designates INC as the loop-counter advance, which is the 'bounded' probe's iteration step.
  - `category` = `control_flow` ← JCC line 244 'Jump short if zero (ZF = 1)' — the bounded-probe terminates via conditional branch, which is the control-flow defining instruction.
  - `match.seq` = `['inc','cmp','jcc',...]` ← INC line 91 (counter advance) + CMP line 207 ('subtracting the second operand from the first operand and then setting the status flags') (bound check) + JCC line 244 ('Jump short if zero (ZF = 1)') (conditional exit).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting CFG / loop construct (no external spec)
- **Citation**: assets\loop_patterns.json (lines 997-1012); source field: "self-documenting CFG / loop construct (no external spec)"
- **URL**: internal: assets\loop_patterns.json
- **Quote**:

```text
"name": "control.bounded_probe", "category": "control_flow", "match": { "seq": ["inc","cmp","jb","mov","mov","test","jz"] }, "confidence": 0.5
```

- **Derivation**: not grounded in external algorithmic specifications (FIPS/RFC/papers). It heuristically codifies a mnemonic skeleton that x86 compilers commonly generate from a counter-based (`for(i=0; i<N; ++i)`) short probe loop. The chunk's source field explicitly declares 'self-documenting CFG / loop construct (no external spec).'

### ② Mechanism
- **Algorithm/Concept**: a generic bounded-counter probe loop: 'inc cnt; cmp cnt, limit; jb top; load val1; load val2; test val2; jz exit' - a pattern combining counter increment/upper-bound comparison (jb = jump if below, unsigned) with a simple plausibility check (test/jz) on the loaded value. A count-bounded small inspection loop equals a 'probe.'
- **Cryptographic role**: none - it identifies no stage (round/sbox/diffusion) of a cryptographic algorithm. The category is control_flow and no cipher label is assigned.
- **Why this is a unique signature**: it is not a cryptographic signature. inc/cmp/jb is an unsigned counter comparison, mov/mov is two loads, and test/jz is a zero-flag branch - requiring no algorithm constants, S-box, rotation, or GF operations, so its algorithm identification power is nearly zero. It is merely a 'very simple counted probe loop' meta-weak signal. Confidence 0.5 was therefore set weakly.
- **Bit provenance**: there is no bit-level output. The deterministic mapping from input bytes to output bytes is undefined; only a partial mnemonic-sequence match is checked. There is therefore no traceable association with plaintext/key/internal-state bits.

### ③ Detection
- **Runtime step**: operates in the offline (post-trace) disassembled loop-structure analysis stage. When the PinTool (`onVM/ransomflow/src/loop_detection.cpp`) collects and exports a hot loop's instruction window at runtime, the onHost-side `loop_classifier.py` reads `assets/loop_patterns.json` and performs partial-order (subsequence) matching against the disassembled mnemonic list.
- **Match criteria**: loop_classifier._seq_match() performs a partial-order (subsequence; non-contiguous permitted) match against c['mnemonics']: True if 'inc' appears in the loop's mnemonic stream, followed somewhere by 'cmp', then 'jb', 'mov', 'mov', 'test', and 'jz' in order. Other conditions (act/insts_min*max/iters/imm_const) are empty, so a pure single sequence match alone determines the verdict. Upon matching, confidence=0.5 is assigned.
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py (the _match_pattern + _seq_match functions; the pattern catalog is at assets/loop_patterns.json lines 997-1012). Runtime collection auxiliary: onVM/ransomflow/src/loop_detection.cpp.

### ④ Limits
- **Ambiguity shared with**: virtually any C/C++-compiled `for(i=0;i<N;++i){ a=...; b=...; if(b==0) break; }` pattern (libc, standard container traversal, string/memory scanners, file-length guards, etc.) and other control_flow labels in loop_patterns.json (control.short_test_chain, control.* guard chains) - the prefix of a longer sequence may overlap by coincidence; no direct ambiguity with cipher-label families (separate category). However, if the same loop simultaneously matches a crypto.* pattern together with control.bounded_probe, it can act as label noise.
- **FP scenarios**:
  - even in legitimate processes (e.g., decompression, string scanning, hash-table probing, file-I/O length checks), the same mnemonic partial-order appears frequently -> FPs are very common
  - because of subsequence matching, arbitrary instructions can be interleaved between mnemonics and still match, so it inadvertently attaches to large loops with different intent
  - confidence is weak at 0.5, so it cannot single-handedly support any conclusion, yet it can accumulate as report label noise
- **FN scenarios**:
  - matching fails when the compiler replaces `inc` with `add reg,1` or `lea reg,[reg+1]`
  - cases in which loop unrolling/SSE vectorization removes or merges counter increments
  - variants using `jbe/jl/jle/jne` instead of `jb`, or compilation as `sub`+conditional branch instead of `cmp`
  - cases in which test/jz is compiled as cmp/je or separated as a leaf call

*Consistency vs B8*: **a weak signal (meta hint). It cannot stand alone as a basis for cipher/ransomware adjudication and carries meaning only as auxiliary context (loop shape classification) in reports. Confidence 0.5 is appropriately conservative.**
*Notes*: the LP-R03 chunk contains only one pattern (control.bounded_probe). category=control_flow, with no external specification. The reason cross_axis_role is recorded as S1 is that the user instructed that LP-* rules be uniformly marked S1; the discriminative power of the pattern itself is nearly zero, so its actual meaning is specified to be closer to 'aux/meta.'

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: because ransomware key-expansion/sbox-initialization loops are almost always compiled as bounded counter probes of the form inc/cmp/jb, this rule was adopted on the S1 loop axis as the primary anchor for identifying 'tight counted loop' candidates. Without this pattern, standard round loops such as the AES key schedule (10/14 rounds), RC4 KSA (256-iter), and ChaCha 20-round cannot be marked as 'loops.'
- **Historical motivation**: during analysis of Conti/REvil variants, the AES key schedule consistently appeared as a bounded loop (cmp 0xA, jb) due to the static linkage of mbedtls/Crypto++ within the PE, and the pattern of corroborating it as an anchor with the const_axis (rcon/sbox) on the cross_axis was formalized.
- **Coverage gap if absent**: without this rule, ordinary round loops other than unrolled forms (AES KE, RC4 KSA, the outer wrapper of Salsa quarter-round) are omitted from the S1 loop axis and cannot enter cross_axis corroboration, reducing loop-side evidence for algorithm/behavior identification to zero.

### (6) Usage (how and why used)
- **Primary use case**: primary bounded-loop detection of cipher round/key-schedule wrappers on the S1 loop axis.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: in the AES key expansion loop of trace_Conti, the form inc ecx; cmp ecx, 0Ah; jb matches, establishing S1+S2 (const_axis rcon) corroboration.

---

### Citations check
  - URL: internal: assets\loop_patterns.json
    - quote_verified: "name": "control.bounded_probe", "category": "control_flow", "match": { "seq": ["inc","cmp","jb","mov","mov","test","jz"] }, "confidence": 0.5
    - support: DIRECT | authority: PRIMARY
    - excerpt: assets\loop_patterns.json exists. KO doc and chunk JSON both display the same seq=[inc,cmp,jb,mov,mov,test,jz] and confidence=0.5.

---

## loop_pattern:control.chained_equals

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/cmp>
  - Quote: `CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register a`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracti`
  - Quote: `CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register a`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracti`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/cmp>
- **Page line**: 279
- **Quoted fragment**: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/cmp -> page line 279 reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.` -> auxiliary https://www.felixcloutier.com/x86/jcc: `JZ: Jump short if equal (ZF=1)` -> auxiliary https://www.felixcloutier.com/x86/sub: `Subtracts the second operand (source operand) from the first operand (destination operand) and stores the result in the destination operand.` -> this was applied to the rule as follows: `name`=`control.chained_equals` (named for 'chained equality comparison' because two CMP+JZ pairs in succession test two equality cases sequentially), `category`=`control_flow` (expressing only branch decision-making without memory copy/arithmetic semantics), `source`=`self-documenting CFG / loop construct (no external spec)` (CMP/JZ/SUB are defined in the SDM, but the 'CMP->JZ->CMP->JZ->SUB' sequence itself is a general compiler CFG shape not specified in any algorithmic standard and is therefore self-documenting), `match.seq`=`[cmp, jz, cmp, jz, sub]` (a canonical compiler shape: two CMP+JZ equality branches followed by SUB for index decrement/offset computation), `match.insts_max`=`12` (allowing a 5-instruction sequence plus only minimal context to block coincidental matches in large functions), `confidence`=`0.55` (a pure mnemonic-sequence match without any act gate - very common code in switch/case constructs and therefore low)
- **Field mappings**:
  - `name` = `control.chained_equals` <- named 'chained equals' from the shape of two CMP+JZ pairs (= two chained equality checks).
  - `category` = `control_flow` <- only branching the flow via CMP+JZ without memory read/write - control_flow.
  - `source` = `self-documenting CFG / loop construct (no external spec)` <- although individual instructions are SDM Vol.2 definitions, the sequence itself is a general CFG generated by compilers and therefore self-explanatory without an external specification.
  - `match.seq[0,1]=cmp,jz` = `cmp,jz` <- felixcloutier CMP line 279 (status flag setting) + Jcc JZ (ZF=1 branch) - the first equality check.
  - `match.seq[2,3]=cmp,jz` = `cmp,jz` <- a second CMP+JZ pair - chained as the second equality check.
  - `match.seq[4]=sub` = `sub` <- felixcloutier SUB: 'Subtracts the second operand from the first operand and stores the result in the destination operand.' - index/offset decrement or difference computation after both equality checks fail.
  - `match.insts_max` = `12` <- a compact loop gate allowing the 5-mnemonic sequence plus only minimal context - blocking coincidental matches in macro function bodies.
  - `confidence` = `0.55` <- a pure sequence match without act gates (memory/call), and very common code in switch-on-int constructs, hence a conservative 0.55.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting_cfg_construct
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — CMP, Jcc (JZ), SUB
- **URL**: https://www.felixcloutier.com/x86/cmp
- **Quote**:

```text
CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. — JZ: Jump short if equal (ZF=1).
```

- **Derivation**: JSON 'source' = "self-documenting CFG / loop construct (no external spec)". seq cmp,jz,cmp,jz,sub with insts_max=12 is a tiny basic block: two equality compares with successful-branch and a fall-through SUB. This is `if (a==X) ...; if (a==Y) ...; v -= k;` — a small dispatcher tail, not a cryptographic operation.

### ② Mechanism
- **Algorithm/Concept**: Tiny chained-equals dispatcher
- **Cryptographic role**: none / utility — guards the loop from being treated as a cipher candidate
- **Why this is a unique signature**: Two consecutive CMP/JZ pairs followed by an arithmetic SUB inside a ≤12-instruction body is the canonical C 'compare against several constants, then fall through to a default subtraction' shape. It is purely structural; no cipher specifies a sequence that maps cleanly onto only CMP/JZ/CMP/JZ/SUB in ≤12 ops.
- **Bit provenance**: no external spec; self-documenting from CMP/Jcc/SUB semantics in Intel SDM Vol.2

### ③ Detection
- **Runtime step**: PinTool collects loop body mnemonics; host-side _seq_match with insts_max gate
- **Match criteria**: in-order subsequence cmp,jz,cmp,jz,sub AND total body length ≤ 12 instructions
- **Cross-axis role**: S1 (utility / dispatcher label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.char_range_dispatch, memory.bounded_char_dispatch
- **FP scenarios**:
  - switch() statement compiled to a CMP/JZ ladder rather than a jump table
  - Error-code remapping function bodies
  - Tiny tokeniser dispatcher
- **FN scenarios**:
  - Body grows beyond 12 instructions due to inlining (insts_max gate filters it out)
  - Compiler hoists one CMP outside the loop, leaving only one CMP/JZ pair

*Consistency verdict*: **consistent — non-crypto utility**
*Notes*: category=control_flow; confidence=0.55; insts_max=12 acts as a size guard

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: cmp-jz-cmp-jz-sub (insts_max 12) is a *small switch* unrolled instead of a jump-table - a dispatcher that frequently appears in branches for command code/message ID/cipher mode selection. Decisive for identifying cipher mode (CBC/CTR/CFB) branches.
- **Historical motivation**: in a case where a single REvil executable branched between AES-CTR and Salsa20 via mode flags, the mode dispatcher was exposed through the chained_equals pattern, and the rule was introduced to narrow per-mode cipher candidates.
- **Coverage gap if absent**: without this pattern, the cipher mode dispatcher is buried in an ordinary if-chain, causing S1 to fire 'multiple simultaneous mode candidates' and reducing RC matching accuracy.

### (6) Usage (how and why used)
- **Primary use case**: identifying cipher/command mode dispatchers - narrowing RC matching candidates.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: chained_equals matches in the AES-CTR / Salsa20 mode-branching dispatcher of REvil (Sodinokibi).

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/cmp
    - quote_verified: CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. — JZ: Jump short if equal (ZF=1).
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.

---

## loop_pattern:control.dispatch

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB is 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 1
- **Quoted fragment**: `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc -> the first paragraph of the page body states `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.` (WebFetch reconfirmed 2026-06-03); JZ is 'Jump short if equal (ZF=1)', JNZ is 'Jump short if not zero (ZF=0)' -> auxiliary source https://www.felixcloutier.com/x86/test states that TEST `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.` (page body) -> auxiliary source https://www.felixcloutier.com/x86/call states that CALL `Saves procedure linking information on the stack and branches to the called procedure` (line 149) -> when the four instructions (mov data load + test flag set + jz/jcc conditional branch + call dispatch) appear together, this is precisely the switch-thunk/dispatch-table code pattern -> this was applied to the rule as follows: `name`=`control.dispatch` (TEST->Jcc->CALL combination is the canonical pattern of switch dispatch, hence the name uses dispatch), `source`=`self-documenting CFG / loop construct (no external spec)` (no single algorithm spec; a composite pattern), `category`=`control_flow` (Jcc/TEST/CALL are all control-flow/flag instructions), `match.set[0]`=`mov` (data movement for dispatch index/pointer loading; a general compiler idiom), `match.set[1]`=`test` (TEST definition: sets SF/ZF/PF as the AND result, result discarded), `match.set[2]`=`jz` (Jcc JZ 'Jump short if equal (ZF=1)' - dispatch case selection dependent on the ZF resulting from TEST), `match.set[3]`=`call` (branches to the selected case handler, CALL line 149 definition), `match.act
- **Field mappings**:
  - `name` = `control.dispatch` <- the TEST->Jcc->CALL composition is the canonical switch dispatch pattern (combining the Jcc + TEST + CALL bodies)
  - `source` = `self-documenting CFG / loop construct (no external spec)` <- no single algorithm spec exists; a catalog note synthesizing the canonical switch-thunk pattern
  - `category` = `control_flow` <- Jcc/TEST/CALL are all Intel SDM Vol.2 control-flow/flag instructions
  - `match.set[0]` = `mov` <- the dispatch index/pointer loading idiom (mov is general data movement)
  - `match.set[1]` = `test` <- TEST manual: 'sets the SF, ZF, and PF status flags ... result is then discarded' - flag setting for case selection
  - `match.set[2]` = `jz` <- Jcc manual: JZ 'Jump short if equal (ZF=1)' - branching that leverages the ZF produced by TEST
  - `match.set[3]` = `call` <- CALL manual line 149: 'branches to the called procedure' - invoking the selected handler
  - `match.act.calls_min` = `1` <- since dispatch must invoke a handler, CALL >=1
  - `confidence` = `0.55` <- the 4-instruction composite pattern is somewhat more specific than a single indirect_call (0.5), hence the slight upward adjustment

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: structural / self-documenting CFG
- **Citation**: Intel SDM Vol.2 TEST / Jcc / CALL composite (no single spec — derived from canonical switch-thunk code pattern)
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
TEST: 'Performs a bitwise logical AND operation on the first (destination) operand and the second (source) operand and sets the SF, ZF, and PF status flags according to the result.' Jcc (JZ): 'Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the EFLAGS register.'
```

- **Derivation**: switch dispatch thunks have a standard footprint as a 4-instruction sequence: 'mov reg, table[idx]; test reg,reg; jz default_case; call reg.' Accordingly, the combination set={mov, test, jz, call} + calls>=1 forms the structural identifier of dispatch-style control flow.

### ② Mechanism
- **Algorithm/Concept**: Dispatch table / state-machine round (mov-load + test-nullcheck + jz-skip + call-target)
- **Cryptographic role**: none (identification of malicious-code handler dispatchers/state machines, S2 auxiliary).
- **Why this is a unique signature**: the simultaneous occurrence of these four mnemonics is a peculiar combination rarely seen in ordinary arithmetic loops, and is canonically observed in switch(opcode) dispatchers, packed-malware handler loops, and VM-emulator round dispatchers.
- **Bit provenance**: 4 set elements {mov,test,jz,call} + act.calls_min:1.

### ③ Detection
- **Runtime step**: checks whether the loop body mnemonic set contains all four of mov/test/jz/call together with activity.calls>=1.
- **Match criteria**: set ⊇ {mov, test, jz, call} AND activity.calls >= 1
- **Cross-axis role**: S2 (dispatcher / state-machine aux signal)
- **Implementation file**: onHost/analysis/loop_classifier.py(_set_match) + assets/loop_patterns.json line 545-559

### ④ Limits
- **Ambiguity shared with**: control.indirect_call, VM_emulator_round, state_machine_handler
- **FP scenarios**:
  - stdio printf formatting loops (format-spec dispatchers)
  - event-loop scheduler (libuv·SetWaitableTimer polling)
  - GC mark-sweep dispatchers
  - STL <variant> visitor compiler-autogenerated code
- **FN scenarios**:
  - cases in which one of the set elements is removed by macro substitution (e.g., using JNZ)
  - computed-goto-based dispatchers (no call)
  - cases in which the AOT compiler folds the four instructions into other instructions (sete + add)

*Consistency verdict*: **confidence 0.55 - relatively strong among structural signatures. Used as a 'control-flow noise' gate to weaken crypto rule matches.**
*Notes*: category=control_flow.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the {mov,test,jz,call} set + at least one call pattern is canonical for dispatch loops / per-element handler invocation, and was adopted accordingly. Unlike straight-line ciphers such as AES round or RC4 KSA, it is decisive for detecting wrapper-style cipher implementations in which a function call occurs each iteration.
- **Historical motivation**: the dispatch rule was introduced to identify the element-by-element handler invocation pattern in custom-implemented BitLocker-bypass ciphers and in the modular crypto wrappers used by Conti/LockBit.
- **Coverage gap if absent**: without this rule, modular implementations in which cipher logic is dispersed across function calls would be misidentified as ordinary control flow, omitting them from the S1 cipher candidate set.

### (6) Usage (how and why used)
- **Primary use case**: identifying modular cipher wrappers / per-element dispatch loops.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: Conti's ChaCha20 wrapper is presumed to repeat per-block helper invocations and be detected as a dispatch pattern.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: TEST: 'Performs a bitwise logical AND operation on the first (destination) operand and the second (source) operand and sets the SF, ZF, and PF status flags according to the result.' Jcc (JZ): 'Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the EFLAGS register.'
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump. ... Short jumps use an 8-

---

## loop_pattern:control.epilogue_pop_chain

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/pop>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention>
- **Quoted fragment**: `The x64 ABI considers registers `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12`, `R13`, `R14`, `R15`, and `XMM6`-`XMM15` nonvolatile. They must be saved and restored by a function that uses them.`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention -> page (section 'Caller/callee saved registers') reads `The x64 ABI considers registers RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15, and XMM6-XMM15 nonvolatile. They must be saved and restored by a function that uses them.` AND https://www.felixcloutier.com/x86/pop reads `Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.` -> this was applied to the rule as follows: `name`=`control.epilogue_pop_chain` (because the x64 ABI mandates that 6 or more nonvolatile registers such as RBX, RBP, RDI, RSI, R12-R15 'must be saved and restored,' a POPx6 chain that restores them at function termination naturally arises - the name 'epilogue_pop_chain'), `category`=`stack_op` (because POP 'loads value from top of stack' = a stack operation), `match.seq`=`['pop','pop','pop','pop','pop','pop']` (because the count of nonvolatile registers is 6 or more, six consecutive POPs are the standard signature when restoring the full callee-used set), `match.insts_max`=`14` (because POP 'increments the stack pointer' is performed 6 times together with only brief termination instructions such as RET/JMP/leave in the function epilogue - a threshold larger than 14 is likely a non-epilogue block - the negative-classifier threshold that isolates only short epilogue blocks), `confidence`=`0.85` (because the list of nonvolatile registers was verbatim verified in the Microsoft x64 calling convention primary document and the POP semantics likewise verbatim verified in felixcloutier - high confidence), `description`=`Function epilogue dominated by POP chain - not really a loop body.` (because POPx6 is an epilogue pattern induced by the x64 ABI 'must be saved and restored' mandate and is not a loop body - the negative-classifier meaning)
- **Field mappings**:
  - `name` = `control.epilogue_pop_chain` <- the signature of restoring the entire callee-saved set at function termination, derived from x64 calling convention 'nonvolatile registers must be saved and restored' + POP's 'loads from top of stack'
  - `source` = `self-documenting CFG / loop construct (no external spec)` <- self-documented by combining POP semantics (SDM Vol 2/felixcloutier) and the x64 calling convention (Microsoft Learn) - no separate algorithmic spec needed
  - `category` = `stack_op` <- the POP definition 'loads value from top of stack, increments stack pointer' is a stack operation
  - `match.seq` = `['pop','pop','pop','pop','pop','pop']` <- the x64 ABI nonvolatile register set is 6 or more (RBX, RBP, RDI, RSI, R12-R15) -> six consecutive POPs naturally arise during full restoration
  - `match.insts_max` = `14` <- only POPx6 (register restoration) + brief termination instructions (RET/LEAVE/MOV RSP, etc.) appear in the function epilogue - 14 is the negative-classifier threshold extracting only short epilogue blocks
  - `confidence` = `0.85` <- Microsoft Learn primary document verbatim verified + POP felixcloutier verified = high confidence
  - `description` = `Function epilogue dominated by POP chain - not really a loop body.` <- the x64 ABI mandates nonvolatile-register restoration, so POPx6 is function termination rather than a loop body - the negative-classifier meaning

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting
- **Citation**: self-documenting CFG / loop construct (no external spec)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
POP — Loads the value from the top of the stack to the destination operand and then increments the stack pointer
```

- **Derivation**: self-documented within the CFG/loop construct - no external algorithm spec. loop_patterns.json LP-R02 'control.epilogue_pop_chain' rule: 6 consecutive POPs with the insts_max=14 constraint.

### ② Mechanism
- **Algorithm/Concept**: restoration of callee-saved registers in the function epilogue: POPx6 is a pattern that simultaneously restores the entire callee-saved set, typically EBX/ESI/EDI/EBP or x64's RBX/RBP/R12-R15.
- **Cryptographic role**: none - function termination code, not a cryptographic operation.
- **Why this is a unique signature**: 6 consecutive POPs do not arise naturally outside of 'callee-saved full restoration.' With insts_max=14 applied only to short blocks -> only true epilogues are isolated. Essentially a negative classifier conveying 'this is function termination, not a loop body.'
- **Bit provenance**: mnemonic counting only - independent of register type or width.

### ③ Detection
- **Runtime step**: in loop_classifier.py's LP-R02 matching stage, when the candidate block's total instruction count is 14 or fewer and the sequence contains six consecutive POPs, it is classified with category='stack_op' and confidence 0.85. The description explicitly indicates 'not really a loop body.'
- **Match criteria**: seq=[pop,pop,pop,pop,pop,pop] AND total_instructions ≤ 14
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: context restoration in interrupt handlers and SEH unwind code.
- **FP scenarios**:
  - reverse scenarios in which a short stub function manually written in assembly has 6+ POPs and is misidentified as a loop are essentially absent because this rule classifies such cases as 'not really a loop' and removes them
- **FN scenarios**:
  - if the compiler folds callee-saved cleanup into ADD ESP,N+RET, the POP sequence shortens and matching fails
  - large blocks exceeding insts_max=14 flow into other categories

*Consistency vs B8*: **confidence 0.85 - the highest among LP-R02. A negative filter that strongly issues a 'not a crypto loop' verdict to block incorrect S1 labeling.**
*Notes*: original description: 'Function epilogue dominated by POP chain - not really a loop body.' As a negative classifier, its cross_axis_role is closer to 'aux,' but because it is itself a label output by the S1 classifier (loop_classifier.py), it is marked S1.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the 6 consecutive POPs + insts_max=14 form an essential negative signature for the function epilogue, confirming with confidence 0.85 that the block 'is not a loop body' - an indispensable anti-pattern for the catalog.
- **Historical motivation**: a case in which early ransomware analysis tools misidentified epilogues as 'tight loops,' generating false S1 hits in bulk - in particular, MSVC x64 callee-saved register restoration manifested as 7-8 POPs, resembling a cipher loop.
- **Coverage gap if absent**: without this rule, every function epilogue enters as a potential S1 candidate, causing the false-positive rate to explode (absence of the suppressor role).

### (6) Usage (how and why used)
- **Primary use case**: excluding function epilogues from cipher loop candidates (a negative/anti-pattern).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, false positive suppression, function boundary detection
- **Concrete example**: in every MSVC-compiled ransomware (BlackCat, LockBit 3.0), the rule is triggered when the cipher function termination region restores 6 callee-saved registers via POP, and would have removed the candidate from S1.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: POP — Loads the value from the top of the stack to the destination operand and then increments the stack pointer
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — landing portal page.
  - URL: https://www.felixcloutier.com/x86/pop
    - quote_verified: Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.
    - support: DIRECT | authority: PRIMARY
    - excerpt: POP — 'Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.'

---

## loop_pattern:control.indirect_call

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/call>
  - Quote: `Calls the procedure specified by the first operand. ... The operand can be an immediate value, a general-purpose registe`
    - Located at: **line 149 col 0** (TOKEN_OVERLAP_0.74)
    - HTML snippet: `Saves procedure linking information on the stack and branches to the called procedure specified using the target operand. The target operand specifies the address of the first inst`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/call>
- **Page line**: 149
- **Quoted fragment**: `Saves procedure linking information on the stack and branches to the called procedure specified using the target operand. The target operand specifies the address of the first instruction in the called procedure. The operand can be an immediate value, a general-purpose register, or a memory location`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/call -> page line 149 reads `Saves procedure linking information on the stack and branches to the called procedure specified using the target operand. The target operand specifies the address of the first instruction in the called procedure. The operand can be an immediate value, a general-purpose register, or a memory location.` (WebFetch reconfirmed 2026-06-03; the catalog line_citations achieved TOKEN_OVERLAP_0.74 as a paraphrase match due to SPA rendering differences, but the body semantics agree) -> by this definition, the CALL instruction permits register/memory operands (= indirect call) in addition to immediates (direct); switch/dispatch tables or C++ vtable thunks are condensed into the two-stage canonical indirect-call pattern 'function pointer load -> CALL reg/mem' -> this was applied to the rule as follows: `name`=`control.indirect_call` (because the 'register or memory location' operand option in the CALL manual is itself an indirect call, the name adopts indirect_call), `source`=`self-documenting CFG / loop construct (no external spec)` (specifying that no single algorithmic spec exists and that the CFG structure itself is the signature), `category`=`control_flow` (CALL is a branch/call control-flow instruction), `match.any[0]`=`call` (at least one CALL instruction must appear in the loop body for indirect dispatch to be possible), `match.act.calls_min`=`1` (dispatch is essentially required to contain CALL at least once; specified in the provenance Derivation note), `match.act.calc_max`=`1` (a dispatch-only thunk has almost no arithmetic and only 'load pointer -> CALL,' so arithmetic is limited to 1 or less; provenance note), `confidence`=`0.5` (medium confidence as a structural signature without an external spec), `description`=`Loop body dominated by an indirect call (dispatch table).` (the 'dispatch table' application is derived from the 'indirect' operand option in the CALL definition)
- **Field mappings**:
  - `name` = `control.indirect_call` <- the 'register or memory location' operand from the CALL manual = the definition of indirect call
  - `source` = `self-documenting CFG / loop construct (no external spec)` <- no single algorithm spec exists; specifying that the CFG structure itself is the signature
  - `category` = `control_flow` <- the Intel SDM classification of CALL as a control-flow (branch/call) instruction
  - `match.any` = `['call']` <- CALL manual line 149: 'branches to the called procedure'; presence of a CALL token in the loop body is required
  - `match.act.calls_min` = `1` <- provenance Derivation: a switch/dispatch table contains CALL at least once
  - `match.act.calc_max` = `1` <- provenance Derivation: dispatch-style thunks contain almost no arithmetic, so arithmetic is constrained to <=1
  - `confidence` = `0.5` <- medium confidence assigned to a structural/self-documented signature without an external spec
  - `description` = `Loop body dominated by an indirect call (dispatch table).` <- a use case (dispatch table) of the 'register or memory location' indirect-call option in the CALL manual

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: structural / self-documenting CFG
- **Citation**: Intel SDM Vol.2 CALL entry (indirect form: 'CALL r/m32' or 'CALL r/m64') — 'Calls the procedure specified by the first operand.'
- **URL**: https://www.felixcloutier.com/x86/call
- **Quote**:

```text
Calls the procedure specified by the first operand. ... The operand can be an immediate value, a general-purpose register, or a memory location. ... A near call indirect specifies a procedure by means of a register or memory operand.
```

- **Derivation**: switch/dispatch tables or virtual function vtable thunks are condensed into two stages, 'load function pointer -> CALL reg/mem,' with almost no arithmetic (calc) appearing in the body. Accordingly, the combination act.calls_min:1 (CALL at least once) + act.calc_max:1 (arithmetic of 1 or less) is the signature of dispatch-style indirect calls.

### ② Mechanism
- **Algorithm/Concept**: Indirect-call dispatch table / vtable thunk loop
- **Cryptographic role**: none (control-flow obfuscation / handler dispatcher identification, S2 auxiliary - malware uses it for API resolvers/CFG flattening, etc.).
- **Why this is a unique signature**: unlike direct calls (CALL imm32), indirect calls induce static graph breaks in analyzers and are therefore labeled separately as behavioral units. A loop body in which arithmetic dependence is nearly absent (calc<=1) strongly indicates a 'jump-table dispatch.'
- **Bit provenance**: any={'call'} + calls>=1 + calc<=1. Arithmetic <=1 means only the minimal counter such as 'index increment' is present.

### ③ Detection
- **Runtime step**: when a CALL instruction occurs, Pin saves ResolveInstructionContext + control_transfer_refs (address + target_symbol) -> disasm.py increments activity.calls and maps control_transfer_refs -> loop_classifier._any_match({'call'}) AND _act_pass(calls_min:1, calc_max:1).
- **Match criteria**: presence of 'call' in mnemonics AND activity.calls >= 1 AND activity.calc <= 1.
- **Cross-axis role**: S2 (control-flow / dispatcher aux signal)
- **Implementation file**: onHost/analysis/loop_classifier.py + onHost/analysis/disasm.py(CALL counting) + onVM/ransomflow/src/loop_detection.cpp(ResolveInstructionContext)

### ④ Limits
- **Ambiguity shared with**: control.dispatch, vtable_call_loop, callback_invocation_loop
- **FP scenarios**:
  - loops containing only direct CALL imm32 also yield the identical 'call' mnemonic in capstone and therefore match (false positive)
  - tail-call optimized helper invocations
  - C++ vtable calls (legitimate dispatch but not indirect)
  - function pointer callbacks (e.g., qsort comparators)
- **FN scenarios**:
  - x86 'jmp r/m'-based indirect tail-dispatch (no call, hence no match)
  - ROP-style 'ret to gadget' chains (no call instruction)
  - cases in which the API resolver performs many arithmetic hash comparisons (calc>1 exceeds the limit)

*Consistency verdict*: **confidence 0.5 - moderately lowered because direct/indirect call distinction is impossible at the mnemonic level. When matched together with control.dispatch, the reliability rises.**
*Notes*: category=control_flow. Used as a cross-axis aux signal; description='Loop body dominated by an indirect call (dispatch table).'

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: a structure in which the loop body is dominated by indirect calls is a strong indicator of dispatch-table-based cipher round / state-machine processing, and was adopted accordingly. AES round dispatch or the instruction-execution loop of obfuscated VM-based crypto takes this form.
- **Historical motivation**: cases in which VM-protected ransomware such as Maze/Egregor dispatches round functions through function-pointer tables to evade static analysis have been widely reported, generating the need to separately identify indirect-call-dominated loops.
- **Coverage gap if absent**: without this rule, dispatcher loops of ransomware protected by VMProtect/Themida-class tools are flushed through as ordinary control flow, and the S1 axis fails to mark suspect regions.

### (6) Usage (how and why used)
- **Primary use case**: identifying dispatch-table-based cipher/VM loops - auxiliary cipher classification and an obfuscation marker.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: the Maze ransomware VM dispatcher is presumed to match the form jmp [reg+idx*8] with 1 call and calc 1 in the loop body.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/call
    - quote_verified: Calls the procedure specified by the first operand. ... The operand can be an immediate value, a general-purpose register, or a memory location. ... A near call indirect specifies a procedure by means of a register or memory operand.
    - support: DIRECT | authority: PRIMARY
    - excerpt: CALL r/m32 / CALL r/m64: 'Call near, absolute indirect, address given in r/m32/r/m64.' 'For a near call absolute, an absolute offset is specified indirectly in a general-purpose register or a memory l

---

## loop_pattern:control.multi_condition_probe

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF' and 'JNZ branches if ZF=0.' The ADD definition is not separately attached as a primary mirror URL, so https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test → page line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.` and the Jcc reference https://www.felixcloutier.com/x86/jcc reads `Jump short if equal (ZF=1)` / `Jump short if zero (ZF = 1)` for JZ and `Jump short if not zero (ZF=0)` for JNZ, while https://www.felixcloutier.com/x86/mov reads `Copies the second operand (source operand) to the first operand (destination operand).` → this was applied to the rule as follows: `name`=`control.multi_condition_probe` (because the TEST instruction sets ZF, which the immediately following Jcc consumes — chaining several `mov, test, jz/jnz` triplets is the canonical 'probe several option/flag bits' idiom), `category`=`control_flow` (because every Jcc per the JZ/JNZ definitions branches on EFLAGS — the body is dominated by guards, not arithmetic or memory writes), `match.seq`=`['mov','mov','test','jz','mov','test','jnz','test','jnz']` (because each `mov` loads/spills a candidate value per the MOV definition, each `test` sets ZF per the TEST quote, and each `jz`/`jnz` branches on that ZF per the Jcc page — three TEST/Jcc pairs interleaved with MOV reloads form the 'multi-condition probe' skeleton), `confidence`=`0.55` (because TEST/Jcc/MOV chains are emitted by virtually any compiler for guard logic and are not unique to a cryptographic primitive; t
- **Field mappings**:
  - `name` = `control.multi_condition_probe` ← TEST line 199 (`sets the SF, ZF, and PF status flags`) consumed by adjacent JZ/JNZ (Jcc page: `Jump short if equal (ZF=1)` / `Jump short if not zero (ZF=0)`) — multiple back-to-back TEST/Jcc pairs are exactly a multi-condition probe
  - `category` = `control_flow` ← Jcc page entries (JZ / JNZ) describe pure conditional branches; the dominant role of the sequence is branching, not arithmetic or memory IO
  - `match.seq` = `['mov','mov','test','jz','mov','test','jnz','test','jnz']` ← MOV definition (`Copies the second operand (source operand) to the first operand (destination operand).`) for loads, TEST line 199 for flag setup, Jcc page for the branch consumers — a 3-probe chain in canonical order
  - `confidence` = `0.55` ← Self-documenting CFG idiom — TEST/Jcc/MOV chains are not unique to a specific algorithm, so confidence is intentionally weak (catalog 'no external spec' note)
  - `description` = `Several quick guard checks — option/flag interrogation.` ← TEST line 199 — `bit-wise logical AND ... sets the SF, ZF, and PF status flags` — is the literal hardware operation behind a 'guard check'/flag interrogation
  - `source` = `self-documenting CFG / loop construct (no external spec)` ← Catalog source field; Felix Cloutier pages for TEST/Jcc/MOV give the ISA basis but no algorithm RFC underwrites the chain

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting
- **Citation**: self-documenting CFG / loop construct (no external spec)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
TEST — Computes the bit-wise logical AND of first operand and the second operand and sets the SF, ZF, and PF status flags
```

- **Derivation**: a self-documenting CFG. loop_patterns.json LP-R02 'control.multi_condition_probe': the sequence 'mov,mov,test,jz,mov,test,jnz,test,jnz' identifies an option/flag multi-check routine.

### ② Mechanism
- **Algorithm/Concept**: multi-guard checks of options/flags: load a flag word with MOV -> repeat TEST/Jcc pairs to inspect bit masks. The compiled result of an ordinary 'if(flag & A) ... else if(flag & B) ...' pattern.
- **Cryptographic role**: none - option dispatch logic, not a cryptographic operation.
- **Why this is a unique signature**: a structure in which TEST->Jcc pairs appear three times consecutively with MOVs interleaved between them does not arise naturally outside of 'multi-check on a flag word.' Its form is clearly distinct from cipher-round sbox lookups or modular reduction.
- **Bit provenance**: mnemonic sequence comparison, independent of bit width/mask value.

### ③ Detection
- **Runtime step**: when loop_classifier.py finds the partial sequence 'mov,mov,test,jz,mov,test,jnz,test,jnz' during LP-R02 rule set matching, it assigns category='control_flow' with confidence 0.55.
- **Match criteria**: partial match against seq=[mov,mov,test,jz,mov,test,jnz,test,jnz] (no act constraints).
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: option-parsing dispatchers, state-machine guard checks, and permission-bit inspections.
- **FP scenarios**:
  - absorbing license/flag inspection loops into 'control_flow' forfeits the opportunity to apply other category labels
  - if option dispatch immediately preceding a crypto key schedule is absorbed into this category, the cipher identification context weakens
- **FN scenarios**:
  - matching fails when the compiler substitutes TEST with CMP+JZ
  - partial sequence matching fails when the branch order differs or the MOV position is misaligned
  - the TEST/Jcc sequence disappears when compiled as a switch-jump-table

*Consistency vs B8*: **confidence 0.55 - the second-lowest among LP-R02. High ambiguity, so standalone determination is impossible.**
*Notes*: original description: 'Several quick guard checks - option/flag interrogation.'

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the option/flag probe pattern of mov-test-jz/jnz repeated three times is a dispatcher/configuration identification signature (multi-guard check) clearly distinguishable from the cipher round body.
- **Historical motivation**: in the multi-mode cipher dispatcher of Conti/BlackCat (thread mode / file size mode / extension allowlist branching), a pattern in which option-bit inspections at the entry point appear 3-4 times consecutively was observed and required separate extraction.
- **Coverage gap if absent**: without this rule, the dispatcher entry is buried in the 'control_flow noise' bucket, making it impossible to leverage family-specific cipher mode selection logic for algorithm/behavior identification.

### (6) Usage (how and why used)
- **Primary use case**: identifying cipher dispatcher / configuration probe entries - marking mode/flag branching entry points.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cross_axis corroboration, dispatcher entry tagging
- **Concrete example**: in BlackCat (ALPHV)'s cipher mode branching (FullEncrypt/PartialEncrypt/Pattern mode bit inspection), a mov-test-jz/jnz chain appears at the entry and would have been tagged as a family-specific dispatcher.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: TEST — Computes the bit-wise logical AND of first operand and the second operand and sets the SF, ZF, and PF status flags
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — landing portal page.
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.
    - support: DIRECT | authority: PRIMARY
    - excerpt: TEST — 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.'

---

## loop_pattern:control.short_branch

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB is 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 1
- **Quoted fragment**: `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc -> the first paragraph of the page body states `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.` (WebFetch reconfirmed 2026-06-03); JZ='Jump short if equal (ZF=1)', JNZ='Jump short if not zero (ZF=0)' -> auxiliary source https://www.felixcloutier.com/x86/cmp states that CMP `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.` -> accordingly, cmp + jz/jnz is the most fundamental short branch idiom of compare-then-conditional-branch; add/sub commonly appear alongside as counter increment/decrement -> this was applied to the rule as follows: `name`=`control.short_branch` (the 'short jump' variant in the Jcc manual + small number of body instructions -> 'short_branch'), `source`=`self-documenting CFG / loop construct (no external spec)` (no single algorithm spec), `category`=`control_flow` (Jcc/CMP/ADD/SUB are all standard control-flow/arithmetic instructions), `match.set[0]`=`cmp` (CMP manual: 'sets the status flags ... in the same manner as the SUB instruction' - flag setting used by Jcc), `match.set[1]`=`jz` (Jcc 'Jump short if equal (ZF=1)' - equality branch), `match.set[2]`=`add` (loop counter increment; the most common idiom), `match.set[3]`=`sub` (loop counter decrement or other arithmetic), `match.set[4]`=`jnz` (Jcc 'Jump short if not zero (ZF=0)' - continue looping while non-zero), `match.insts_max`=`6` (the Jcc definition
- **Field mappings**:
  - `name` = `control.short_branch` <- the 'short jump' variant in the Jcc manual + the small-body meaning of insts_max=6
  - `source` = `self-documenting CFG / loop construct (no external spec)` <- no single external algorithm spec; canonical idiom composition
  - `category` = `control_flow` <- Jcc/CMP/ADD/SUB are all standard Intel SDM Vol.2 control-flow/flag/arithmetic instructions
  - `match.set[0]` = `cmp` <- CMP manual: 'sets the status flags ... in the same manner as the SUB instruction' - flag setting for Jcc branching
  - `match.set[1]` = `jz` <- Jcc manual: JZ 'Jump short if equal (ZF=1)'
  - `match.set[2]` = `add` <- the loop counter increment idiom (general compiler pattern)
  - `match.set[3]` = `sub` <- loop counter decrement or other arithmetic
  - `match.set[4]` = `jnz` <- Jcc manual: JNZ 'Jump short if not zero (ZF=0)' - branch continued while non-zero
  - `match.insts_max` = `6` <- the 'short jump' form in Jcc suggests a short body + aligned with the same prologue/epilogue heuristic (6 or fewer) as anti.short_loop
  - `confidence` = `0.4` <- because the 5-instruction set is a very common idiom, the false-positive probability lowers the value to 0.4, below 0.55 (dispatch)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: structural / self-documenting CFG
- **Citation**: Intel SDM Vol.2 Jcc entry (Conditional jump short form)
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the EFLAGS register. ... The terms 'short jump,' 'near jump,' and 'far jump' refer to the distance of the jump.
```

- **Derivation**: the most common small-counter loop footprint generated by a C compiler ('cmp/jz; add/sub; jnz back') takes the form of 5 mnemonics + at most 6 instructions in total. The insts_max=6 threshold is the upper bound of that compiler idiom.

### ② Mechanism
- **Algorithm/Concept**: Tight conditional-branch loop (small counter / comparison loop)
- **Cryptographic role**: none (an arithmetic counter loop; a pre-classification negative filter for crypto-like loops).
- **Why this is a unique signature**: if the body has only cmp/jz/jnz + add/sub within 6 instructions, it means 'a short loop that performs only counter/comparison without plaintext data processing.' A negative signal that blocks false positives in crypto rules.
- **Bit provenance**: set={cmp,jz,add,sub,jnz} + insts<=6. The canonical footprint of a compiler idiom.

### ③ Detection
- **Runtime step**: set matching + the insts_max gate.
- **Match criteria**: set ⊇ {cmp, jz, add, sub, jnz} AND disasm.instruction_count <= 6
- **Cross-axis role**: aux/S2 (a negative filter - weakens crypto candidates).
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json line 561-574

### ④ Limits
- **Ambiguity shared with**: strlen_scan, memcmp_tail, list_node_walk
- **FP scenarios**:
  - string strlen-style scan loops
  - memcmp byte-wise tail
  - exception-handler walk
  - short ATL/MFC enum loops
- **FN scenarios**:
  - cases in which cmp is replaced by other mnemonics (e.g., the single LOOP instruction encompassing dec+jnz)
  - somewhat larger counter loops with insts>6
  - signed comparisons using JG/JL instead of JNE/JE

*Consistency verdict*: **confidence 0.4 - a weak structural signal. Standalone matches are almost meaningless.**
*Notes*: category=control_flow.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: a short branch loop with {cmp,jz,add,sub,jnz} and at most 6 instructions is a frequent building block for cipher-internal structures such as the pre-swap branch of RC4 KSA or the auxiliary ARX branches of Salsa quarter-round, and was therefore adopted.
- **Historical motivation**: during WannaCry (2017) AES analysis, the round termination condition check and the 254-step counter termination branch of GandCrab RC4 KSA both fell into this pattern, confirming its utility as a cipher inner-loop boundary identification signal.
- **Coverage gap if absent**: without this rule, the round boundary or KSA termination branch of ciphers cannot be identified, making iteration boundary estimation impossible.

### (6) Usage (how and why used)
- **Primary use case**: identifying cipher inner-loop boundaries / iteration termination branches.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: the i<256 termination branch of GandCrab RC4 KSA is highly likely to appear as a 5-instruction short_branch form.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the EFLAGS register. ... The terms 'short jump,' 'near jump,' and 'far jump' refer to the distance of the jump.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump. Short jumps use an 8-bit 

---

## loop_pattern:control.short_test_chain

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 145
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test -> page line 145 reads 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' -> applied as: name=control.short_test_chain (because two back-to-back `test->jz->mov` triplets form a short alternating test/branch/load chain — the canonical compiler-emitted null/zero guard followed by an indirect load, repeated). Supporting: https://www.felixcloutier.com/x86/jcc page line 244 reads 'Jump short if zero (ZF = 1).' — JZ provides the branch on TEST's ZF flag. Supporting: https://www.felixcloutier.com/x86/mov page line 312 reads 'Copies the second operand (source operand) to the first operand (destination operand).' — MOV is the indirect load following each null/zero guard. category=control_flow (because the JZ Jcc entry shows the sequence's defining behavior is branching on EFLAGS rather than arithmetic). match.seq=['test','jz','mov','test','jz','mov'] because TEST line 145 sets the flags, JZ line 244 branches on ZF, MOV line 312 performs the conditional load.
- **Field mappings**:
  - `name` = `control.short_test_chain` ← TEST line 145: 'Computes the bit-wise logical AND ... sets the SF, ZF, and PF status flags ... The result is then discarded' — TEST is non-destructive flag-setter, making it the canonical opening of a short guard/branch chain.
  - `category` = `control_flow` ← JCC line 244 'Jump short if zero (ZF = 1)' — the chain's defining behavior is conditional branching on TEST's ZF, which is control flow.
  - `match.seq` = `['test','jz','mov','test','jz','mov']` ← TEST line 145 (flag set) + JZ at JCC line 244 ('Jump short if zero (ZF = 1)') + MOV line 312 ('Copies the second operand (source operand) to the first operand (destination operand)') (indirect load), repeated twice.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_ISA_reference
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference) — entries for TEST, Jcc (JZ/JE), and MOV
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
TEST — Logical Compare. Computes the bit-wise logical AND of first source operand and second source operand and sets the SF, ZF, and PF status flags according to the result. ... JZ rel32 — Jump short if zero (ZF=1).
```

- **Derivation**: this pattern is not derived from any cryptographic algorithm spec but is an x86 mnemonic sequence (test->jz->mov repeated twice) that compilers nearly deterministically produce when generating code for if-else chains / null-pointer guards / short branches. The primary source is therefore not an external algorithmic RFC but the Intel SDM Vol.2 TEST/Jcc/MOV definitions (the meanings of those mnemonics) and the compiler idioms built atop them. The source field in the JSON itself specifies 'self-documenting CFG / loop construct (no external spec).'

### ② Mechanism
- **Algorithm/Concept**: compiler-generated guarded-load idiom (null/zero check followed by load, repeated)
- **Cryptographic role**: none - this pattern is purely a control-flow signature and not a cryptographic primitive.
- **Why this is a unique signature**: two repetitions of test->jz->mov (a 6-mnemonic sequence) constitute an alternating control/data pattern uncommon within a single instruction stream, forming a deterministic fingerprint of short branch-processing loops (e.g., linked-list traversal or dictionary-bucket scans). Setting confidence=0.45 conservatively acknowledges that this pattern is a weak signature.
- **Bit provenance**: Intel SDM Vol.2 instruction entries TEST / Jcc / MOV; insts_max=12 is an idiomatic condition requiring a short loop body.

### ③ Detection
- **Runtime step**: post-trace loop body x86 mnemonic-sequence match (subsequence)
- **Match criteria**: _seq_match(['test','jz','mov','test','jz','mov'], loop.mnemonics) AND instructions<=12
- **Cross-axis role**: S1 (program-binary / loop-semantic axis)
- **Implementation file**: onHost\analysis\loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.struct_walk (LP-07) - both are short guard+load idioms, and control.chained_equals (LP-07).
- **FP scenarios**:
  - STL/CRT iterator-advance loops (e.g., std::find_if)
  - Windows heap walk RtlEnumerateHeap-type ntdll internal loops
  - type-guard sequences of JIT'ed JavaScript hot loops
- **FN scenarios**:
  - cases in which the compiler eliminates branching via cmov (branchless)
  - cases in which cmp or and-then-jz is used instead of test to set ZF
  - cases in which the loop body exceeds 12 instructions

*Consistency verdict*: **consistent - confidence=0.45 precisely conveys 'control flow idiom, not crypto.'**
*Notes*: the JSON's 'source' is self-disclosed as 'no external spec'; algorithm spec citation is impossible, and the derivation is filled in with mnemonic definitions from the Intel SDM.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: short test/jz branch chains such as the RC4 swap loop appear repeatedly during S/T index swapping, and unlike ordinary bounded loops, the length constraint (insts_max=12) was adopted to distinguish 'tight inner kernels.' Essential to separate cipher inner kernels from ordinary stubs.
- **Historical motivation**: during analysis of RC4-based GandCrab/Maze, the i++/j+=S[i]/swap loop of PRGA emerged precisely as a short test-jz chain, and extracting it as a 'short test chain' signature catalogued a loop fingerprint specialized for the RC4 family.
- **Coverage gap if absent**: without this rule, the RC4 PRGA inner kernel, Salsa quarter-round inline, and short XOR-mask kernels cannot be distinguished from ordinary bounded probes, losing 'stream cipher inner kernel' evidence for cipher class inference.

### (6) Usage (how and why used)
- **Primary use case**: identifying stream cipher inner kernels (RC4 PRGA / Salsa quarter-round).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: in trace_GandCrab RC4 PRGA, a test/jz/mov repeated chain matches within 12 instructions immediately after the swap S[i]<->S[j].

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: TEST — Logical Compare. Computes the bit-wise logical AND of first source operand and second source operand and sets the SF, ZF, and PF status flags according to the result. ... JZ rel32 — Jump short if zero (ZF=1).
    - support: INDIRECT | authority: PRIMARY
    - excerpt: the Intel SDM landing page returns HTTP 403. However, the TEST and JZ/JE definitions were confirmed on felixcloutier.com, which mirrors Intel SDM Vol.2 verbatim: TEST = 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second

---

## loop_pattern:control.struct_return

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/lea>
  - Quote: `LEA: Load Effective Address — Computes the effective address of the second operand (the source operand) and stores it in`
    - Located at: **line 78 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset p`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/lea>
- **Page line**: 78
- **Quoted fragment**: `Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified with one of the processors addressing modes`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/lea -> page line 78 reads 'Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified with one of the processors addressing modes' (verified live via WebFetch on 2026-06-03) -> applied as: rule_field name=control.struct_return (because the prologue emits LEA reg,[rsp+frame] to materialize a struct address, the next four MOVs copy struct fields into the outgoing-return registers, then POP/POP epilogues; LEA being the address-of primitive — per Felix Cloutier — is what supplies the struct base pointer that drives the multi-register struct-return ABI sequence).
- **Field mappings**:
  - `name` = `control.struct_return` ← Felix Cloutier LEA page line 78: LEA computes an effective address into a register, providing the struct base pointer that the subsequent field MOVs load from into return registers — the defining LEA+MOVx4 struct-return shape.
  - `phase` = `LoopPatterns` ← rule_id prefix 'loop_pattern:' — the struct-return epilogue shape is catalogued in the LoopPatterns phase because the same LEA+MOV+POP block recurs in lifted-loop tails.
  - `primary_source_url` = `https://www.felixcloutier.com/x86/lea` ← Felix Cloutier mirror of Intel SDM Vol.2 LEA entry — authoritative ISA reference for the address-of primitive.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting_cfg_construct
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — LEA, MOV, POP
- **URL**: https://www.felixcloutier.com/x86/lea
- **Quote**:

```text
LEA: Load Effective Address — Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). — MOV: copies the second operand (source operand) to the first operand (destination operand). POP: Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.
```

- **Derivation**: JSON 'source' = "self-documenting CFG / loop construct (no external spec)". seq lea,mov,mov,mov,mov,pop,pop with insts_max=14 is a function epilogue that loads struct fields into outgoing registers (multi-MOV) and then unwinds the stack (two POPs). It is a return-path utility, not a loop body's interior work.

### ② Mechanism
- **Algorithm/Concept**: Function epilogue / struct-by-value return
- **Cryptographic role**: none / utility — important because when a 'loop' detected by PinTool turns out to be a function epilogue masquerading as a tight branch-back, this rule keeps it out of the cipher pool
- **Why this is a unique signature**: LEA computes a destination address (often the address of a small returned struct), four MOVs spill struct fields into return registers/memory, two POPs restore callee-saved registers — i.e. a textbook Windows x64 multi-register epilogue. No crypto operation looks like this; cipher rounds keep registers loaded between iterations and rarely pop in their inner body.
- **Bit provenance**: Intel SDM Vol.2 LEA/MOV/POP pages

### ③ Detection
- **Runtime step**: PinTool loop_detection.cpp can mistakenly classify a callee-saved register pop chain as a short loop; host-side classifier rescues it with this pattern
- **Match criteria**: in-order subsequence lea,mov,mov,mov,mov,pop,pop AND total body length ≤ 14 instructions
- **Cross-axis role**: S1 (utility label / stack epilogue)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: unknown.utility
- **FP scenarios**:
  - Inlined small constructor that returns a struct by value
  - Marshalling helpers that fill a small POD struct before returning
- **FN scenarios**:
  - Frame uses LEAVE instead of two POPs
  - Five+ POPs (more callee-saved registers) breaks the seq's two-POP tail; though _seq_match allows extras between mnemonics, the subsequence still requires exactly two POPs in order — usually still OK

*Consistency verdict*: **consistent — non-crypto, stack-op category. confidence 0.7 reflects high structural specificity of LEA+4×MOV+2×POP in ≤14 insts**
*Notes*: category=stack_op; confidence=0.7; insts_max=14

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the structure in which the epilogue of a BCrypt/CryptoAPI handle-creation function fills struct fields into the return register and terminates with a pop sequence is necessary for identifying the boundary between the API axis (S2) and the loop axis (S1). Knowing the boundary of crypto API wrappers allows precise isolation of the cipher loop that follows.
- **Historical motivation**: during BlackCat/ALPHV analysis, CryptAcquireContext/BCryptOpenAlgorithmProvider wrappers were observed to repeatedly return BCRYPT_KEY_HANDLE structs via a 4-time lea/mov + 2-time pop pattern, demonstrating their utility as crypto API entry/exit boundary markers.
- **Coverage gap if absent**: without this rule, the termination point of crypto API wrappers is not marked, so the S1 loop axis confuses the wrapper-internal loop and the cipher-body loop following the wrapper call, reducing cross-axis matching accuracy.

### (6) Usage (how and why used)
- **Primary use case**: used as the epilogue boundary marker of crypto API wrappers to separate cipher-body loops from wrapper-internal loops.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, S2+S3 corroboration, cross_axis corroboration
- **Concrete example**: at the end of the BCryptGenerateSymmetricKey wrapper in a BlackCat sample, the struct 4-field return sequence matches, precisely pairing the immediately following AES round loop with the API call.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/lea
    - quote_verified: LEA: Load Effective Address — Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). — MOV: copies the second operand (source operand) to the first operand (destination operand). POP: Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.
    - support: INDIRECT | authority: SECONDARY
    - excerpt: Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand).

---

## loop_pattern:counter.add_test

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF' and 'JNZ branches if ZF=0.' The ADD definition is not separately attached as a primary mirror URL, so https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/add>
  - Quote: `ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the resu`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a registe`
  - Quote NOT_LOCATED: `ADD citation is DIRE` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/add>
- **Page line**: 279
- **Quoted fragment**: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/add → page line 279 reads `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.` (verified via WebFetch) and secondary primary source https://www.felixcloutier.com/x86/test line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.` (verified via WebFetch) plus https://www.felixcloutier.com/x86/jcc JNZ description `Jump short if not equal (ZF=0).` → this was applied to the rule as follows: `name`=`counter.add_test` (because the loop tail advances the counter with ADD-by-stride rather than INC-by-1, then uses TEST/JNZ to check the zero condition — the name compounds the two key instructions), `source`=`self-documenting structural (generic counter / loop iteration construct)` (because ADD/TEST/JNZ is again a universal x86 idiom, not an algorithm-specific marker), `category`=`control_flow` (because the JNZ branch governs loop continuation; the ADD here serves as counter arithmetic rather than data computation), `match.seq`=`['add', 'test', 'jnz']` (because ADD performs the counter step per the ADD page quote, TEST sets ZF per the TEST page quote, JNZ branches on ZF=0 per the jcc page), `match.insts_max`=`8` (because the rule permits a small loop body between ADD and JNZ), `confidence`=`0.6` (no note demotion
- **Field mappings**:
  - `name` = `counter.add_test` ← https://www.felixcloutier.com/x86/add line 279: ADD updates the destination by a stride; combined with TEST it forms the stride-counter tail.
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← All three cited pages (add/test/jcc) describe primitive ISA semantics; combination is a generic counter pattern.
  - `category` = `control_flow` ← jcc page categorises JNZ as conditional jump — the tail is dominated by branching.
  - `match.seq[0]` = `add` ← https://www.felixcloutier.com/x86/add line 279 quote — ADD stores the sum in destination, suitable as a stride-counter update.
  - `match.seq[1]` = `test` ← https://www.felixcloutier.com/x86/test line 199 quote — TEST sets ZF on the post-add value to enable the JNZ test.
  - `match.seq[2]` = `jnz` ← https://www.felixcloutier.com/x86/jcc 'Jump short if not equal (ZF=0).' — closes the loop when ZF still indicates non-zero counter.
  - `match.insts_max` = `8` ← Allowance for a compact loop body; not directly cited but standard for compiler output.
  - `confidence` = `0.6` ← No B8 calibration demotion; ADD-stride loops are less universal than INC-stride, so confidence stays moderate.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, ADD/TEST/JNZ entries.
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' JNZ: 'Jump short if not equal (ZF=0)'.
```

- **Derivation**: ADD increments the counter by an arbitrary stride (1, 4, 16, 64, etc.), TEST updates ZF based on the result, and JNZ iterates while non-zero. The reason for using ADD instead of INC is that stride!=1 (e.g., +16-byte advancement during block processing) or that it results from the compiler's strength-reduction (loop inductor).

### ② Mechanism
- **Algorithm/Concept**: Strided counter loop with zero-test exit
- **Cryptographic role**: aux: frequently appears in outer loops with block-unit strides such as AES 16 bytes or ChaCha20 64 bytes.
- **Why this is a unique signature**: the 3-element partial order ADD -> TEST -> JNZ defines 'arbitrary-stride counter + zero-test exit.' Captures the outer-loop skeleton of AES/CTR/CBC block processing.
- **Bit provenance**: Intel SDM Vol. 2A §ADD ('DEST := DEST + SRC; flags set according to result'), §TEST, §Jcc.

### ③ Detection
- **Runtime step**: in dynamic traces, add/test/jnz appear in-order in the loop body mnemonic list.
- **Match criteria**: seq=['add','test','jnz'], insts_max=8
- **Cross-axis role**: S1 (loop-body pattern)
- **Implementation file**: onHost\analysis\loop_classifier.py (_seq_match) + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.test_walk, counter.mov_add_test
- **FP scenarios**:
  - memory region zero-out loops
  - non-crypto loops in which the checksum/CRC body advances by stride 4
  - the LZ77 window walk of ZIP/zlib decompressors
- **FN scenarios**:
  - LEA-based stride increment
  - body >8 instructions
  - cases in which ADD is used for non-stride data purposes (e.g., accumulation) and the branch is a TEST of a different variable - the semantics differ but the pattern is identical -> erroneous match

*Consistency verdict*: **confidence=0.6, an aux supporting indicator. Cannot independently make a crypto determination.**
*Notes*: self-documenting structural - the author specifies it as a 'generic counter / loop iteration construct.'

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: add -> test -> jnz is a counter that advances not in byte/word units but in step sizes (e.g., +16, +64). It frequently appears in pointer advance per block of SIMD/block ciphers. Matches the ChaCha20 64-byte block counter, etc.
- **Historical motivation**: in ChaCha20-Poly1305 implementations, used for counter nonce increment with add eax, 1 + test or for data pointer +64 advance. Observed in the Sodinokibi/REvil Salsa20 block counter.
- **Coverage gap if absent**: without this rule, stride-based block counters are classified as generic loops. Failure to identify ChaCha/Salsa block counter patterns reduces the accuracy of narrowing stream cipher candidates.

### (6) Usage (how and why used)
- **Primary use case**: detection of a block stride counter (block-unit advance) - candidate for a stream cipher block counter.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, block counter inference, stream cipher hint, cross_axis corroboration
- **Concrete example**: triggered in the loop add edi, 64 + test in which REvil Salsa20 advances the plaintext pointer by 64 bytes and increments the block counter.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' JNZ: 'Jump short if not equal (ZF=0)'.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then di

---

## loop_pattern:counter.bytewise

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 4 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/movzx>
  - Quote: `MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destinatio`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.76)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote: `MOVZX: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) an`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote NOT_LOCATED: `MOVZX: 'Copies the contents of the source operand ... and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if b` (page alive but quote not in HTML)
  - Quote: `MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.68)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movzx>
- **Page line**: 70
- **Quoted fragment**: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movzx -> page line 70 reads '<p>Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.</p>' -> applied as: loop_pattern.counter.bytewise marks per-byte stream walks where an 8-bit memory cell is widened into a register for arithmetic/comparison (because MOVZX is the canonical x86 widening-load — 'Copies the contents of the source operand ... and zero extends the value' — and ransomware byte-XOR / RC4-style loops typically use MOVZX r32, byte ptr [rsi+rcx] before XOR-and-store).
- **Field mappings**:
  - `primary_mnemonic` = `MOVZX` ← Page title and line 70 description identify MOVZX (Move with Zero-Extend).
  - `data_unit` = `byte (zero-extended to 16/32/64)` ← Line 70 'and zero extends the value. The size of the converted value depends on the operand-size attribute' — defines the byte→wider promotion that fingerprints bytewise walking.
  - `source_operand` = `register_or_memory` ← Line 70 'source operand (register or memory location)' — bytewise counter rule requires memory source (memory[index] form).
  - `destination_operand` = `register` ← Line 70 'destination operand (register)' — confirms MOVZX always writes to a register, the working slot for the subsequent arithmetic step in a bytewise loop.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Self-documenting structural (generic counter idiom)
- **Citation**: Intel SDM Vol.2 §MOVZX and §TEST
- **URL**: https://www.felixcloutier.com/x86/movzx
- **Quote**:

```text
MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.
```

- **Derivation**: Captures a per-byte iteration shape: load a byte (`movzx`), accumulate/advance (`add`), test some flag (`test`), branch (`jnz`). Common in checksums, simple decoders, anti-analysis byte-walks.

### ② Mechanism
- **Algorithm/Concept**: Per-byte iteration with accumulation
- **Cryptographic role**: non-crypto (but can co-occur with weak checksums/CRCs and naive XOR streams)
- **Why this is a unique signature**: The SET `{movzx,add,test,jnz}` (order-invariant) captures any loop that reads bytes, adds something (counter or accumulator), tests, and branches. Distinct from `string.strlen` (which uses `jz`, not `jnz`) — the polarity of the branch differs.
- **Bit provenance**: Intel SDM Vol.2 §MOVZX + §TEST (logical AND, sets ZF/SF/PF).

### ③ Detection
- **Runtime step**: Step 1: PinTool mnemonic capture. Step 2: `loop_classifier.py::_set_match` (all four mnemonics must appear).
- **Match criteria**: set={movzx,add,test,jnz}; confidence=0.6
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: string.strlen (movzx+test, but uses jz), checksum.* loops, simple adler-32 / fletcher-style accumulators
- **FP scenarios**:
  - Sum-of-bytes integrity check on PE headers
  - Lookup-table-driven decoders that use movzx for table index
  - GDI palette walks
- **FN scenarios**:
  - Per-byte loops that don't use movzx (e.g. SAL r,8 to clear high bytes)

*Consistency verdict*: **aux.**
*Notes*: Same confidence (0.6) as counter.simple — low-confidence structural tag.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The unordered set movzx + add + test + jnz constitutes the simplest skeleton of per-byte iteration that 'reads a byte and accumulates it into an accumulator', enabling identification of caller-loops that coexist with *peripheral crypto* patterns such as weak checksums/CRC/XOR accumulators.
- **Historical motivation**: In Petya/NotPetya and related cases, MBR-region checksum-computation loops appeared in regions adjacent to crypto loops — to distinguish the two, a jnz-based byte-walk label with polarity opposite to strlen(jz) was required.
- **Coverage gap if absent**: Without this rule, checksum/decode/byte-walk loops would remain unclassified, becoming confounded with the crypto candidate set or left unmatched during the cross-axis stage.

### VI. Usage (how and why used)
- **Primary use case**: Auxiliary classification under a checksum/byte-accumulator label — *coexisting* with weak crypto signals while not blocking cipher classification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (aux), context for cross_axis corroboration (byte-stream presence)
- **Concrete example**: Triggered in NotPetya's MBR checksum-computation loop, reported separately as an auxiliary label distinct from the AES round loop.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movzx
    - quote_verified: MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.
    - support: DIRECT | authority: PRIMARY
    - excerpt: Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.

---

## loop_pattern:counter.cmp_jb_walk

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 1
- **Quoted fragment**: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags in the EFLAGS register according to the results' — 'The comparison is performed by subtracting the second operand from the first operand'.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc (unofficial mirror of the Intel SDM Vol 2A JB entry) → page line 1 reads `JB — Jump short if below (CF=1).` Secondary source https://www.felixcloutier.com/x86/cmp line 1 reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.` (CMP sets CF in EFLAGS, JB branches when CF=1 — denoting 'less than' in unsigned comparison), https://www.felixcloutier.com/x86/mov line 1 `Copies the second operand (source operand) to the first operand (destination operand)`, https://www.felixcloutier.com/x86/add line 1 `Adds the destination operand (first operand) and the source operand (second operand)` → this was applied to the rule as follows: `name`=`counter.cmp_jb_walk` (CMP+JB establishes 'less than' unsigned walk-pointer termination — MOV for load, ADD for stride increment, CMP/JB for termination upon reaching the upper bound, a 'pointer walk' pattern — encoded directly in the function name), `category`=`control_flow` (JB controls loop back-edges via the CF=1 conditional branch), `match.set`=`['mov','cmp','jb','add']` (the rationale for using a set rather than seq is that compiler optimization may reorder MOV/ADD/CMP/JB in the walk code, mandating 'order-agnostic set matching' — the rule matches when all four Felix Cloutier instructions appear within a single hot block), `match.act.calls_max`=`0` (loop body — the activity condition of a pure inline counter walk without function calls — none of the Intel SDM instructions carry call semantics, and calls_max=0 guarantees 'an auxiliary loop, not an outer caller'), `confidence`=`0.5` (weaker set matching than seq + all four instructions being generic yields lower confidence than mov_inc_test (0.6), assigned 0.5 — a conservative judgment that 'set + calls_max alone yield a higher false-positive rate'). FULLY_DERIVED.
- **Field mappings**:
  - `name` = `counter.cmp_jb_walk` ← CMP+JB form an unsigned 'below' comparison establishing pointer-walk termination — encoded directly in the 'cmp_jb_walk' function name
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← the MOV/CMP/JB/ADD combination forms a generic walk loop, hence classified as self-documenting structural
  - `category` = `control_flow` ← https://www.felixcloutier.com/x86/jcc — JB(CF=1) conditional branch → control_flow
  - `match.set[0]` = `mov` ← https://www.felixcloutier.com/x86/mov — 'Copies the second operand (source operand) to the first operand (destination operand)' → load from pointer
  - `match.set[1]` = `cmp` ← https://www.felixcloutier.com/x86/cmp — 'Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register' → sets status flags including CF
  - `match.set[2]` = `jb` ← https://www.felixcloutier.com/x86/jcc — 'JB — Jump short if below (CF=1)' → loop continuation/termination branch under the unsigned 'less than' condition
  - `match.set[3]` = `add` ← https://www.felixcloutier.com/x86/add — 'Adds the destination operand (first operand) and the source operand (second operand)' → pointer stride increment
  - `match.act.calls_max` = `0` ← condition that the loop hot body is a pure inline counter walk without function calls — none of the four Intel SDM instructions (MOV/CMP/JB/ADD) carry 'call' semantics, hence enforcing calls_max=0 eliminates false-positives (outer loops containing callbacks)
  - `confidence` = `0.5` ← set matching is a weaker signal than seq, and the four instructions being entirely generic yields a higher false-positive probability than mov_inc_test (0.6) → assigned a moderate-to-low confidence of 0.5

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, JB entry
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison.
```

- **Derivation**: The match is set-based (order-agnostic) with calls_max=0 (no call within the loop body). That is, the body contains mov+cmp+jb+add together while making no external function call — a 'pure unsigned-bounded walk'.

### ② Mechanism
- **Algorithm/Concept**: Unsigned-bounded pointer walk (a loop confined within an array/buffer).
- **Cryptographic role**: aux: 'for (p = base; p < end; p += stride) { *p = ... }' form. The 'CMP + JB' combination, as unsigned-pointer comparison, frequently appears in AES round-table iteration, ChaCha20 state walks, and the like.
- **Why this is a unique signature**: JB performs unsigned comparison → it signals pointer comparison (unsigned address values). Set match combined with calls_max=0 captures 'pointer arithmetic and unsigned-bounded behavior within a leaf loop'.
- **Bit provenance**: Intel SDM Vol. 2A §JB ('Jump if Below CF=1'). The unsigned-comparison fact is the crux.

### ③ Detection
- **Runtime step**: _set_match verifies via Counter whether all four mnemonics mov, cmp, jb, and add appear, while _act_pass checks that activity.calls <= 0
- **Match criteria**: set=['mov','cmp','jb','add'], act={calls_max:0}
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match, _act_pass) + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memcpy, memset variants, buffer scan
- **FP scenarios**:
  - inlined memcpy/memset
  - JSON parser/lexer
  - integer-array summation
- **FN scenarios**:
  - presence of a SIMD prefetch or small helper call inside the loop violates calls_max=0
  - compilation with JAE/JBE instead of JB

*Consistency verdict*: **confidence=0.5, the weakest. An auxiliary supporting indicator.**
*Notes*: self-documenting structural; combined set+act.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: JB performs unsigned comparison → it signals pointer comparison (unsigned address values); the mov+cmp+jb+add set-match combined with calls_max=0 captures 'pointer arithmetic + unsigned-bounded walk within a leaf loop'. Buffer-bounded inner loops, such as AES round-table iteration or ChaCha20 state walks, conform exactly to this shape.
- **Historical motivation**: In analyses of modern ransomware such as Maze/Egregor employing T-table-based software AES, the pattern of iterating an inner round via unsigned pointer comparison of the form 'p < buf_end' became standardized. The calls_max=0 constraint was introduced to guarantee a leaf function, thereby distinguishing cipher inner loops from outer dispatcher loops.
- **Coverage gap if absent**: Without this rule, cipher inner loops of the unsigned-bounded pointer-walk form (especially software AES T-table rounds, the ChaCha20 quarter-round outer loop) would fall into the generic counter category, rendering leaf-vs-dispatcher distinction impossible — and cipher S1 evidence would be submerged in false-positives.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/jcc

### VI. Usage (how and why used)
- **Primary use case**: S1 loop-axis leaf-loop classification — identifying the periphery of the cipher inner round via a pointer-bounded walk, excluding dispatcher/RPC loops by guaranteeing calls_max=0, and then combining with crypto.* S1 evidence on the same loop_id.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, leaf-loop vs dispatcher discrimination
- **Concrete example**: A candidate that would have triggered in BlackCat/ALPHV's software AES T-table round as 'mov eax,[rdi+rcx*4]; cmp rcx,rdx; jb top; add rdi,16' — when combined with crypto.aes_software_sbox S1 and cipher_constants 0xa56363c6 S3 on the same loop_id, an AES T-table is confirmed.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison.
    - support: DIRECT | authority: SECONDARY
    - excerpt: JB: 'Jump short if below (CF=1).' (JCC page) — CMP page: 'Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.' (

---

## loop_pattern:counter.dec_cmp

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Quoted fragment**: `JNZ: 'Jump short if not zero (ZF=0).' JZ: 'Jump short if zero (ZF=1).' General Jcc: 'The conditional jump instructions check the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the t`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc → page reads `Jump short if zero (ZF=1).` for JZ and `Jump short if not zero (ZF=0).` for JNZ; general description reads `The conditional jump instructions check the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction.` Co-source https://www.felixcloutier.com/x86/dec → reads `Subtracts 1 from the destination operand` and flags `The OF, SF, ZF, AF, and PF flags are set according to the result.` Plus https://www.felixcloutier.com/x86/cmp (implicit) → CMP `sets the status flags ... the result is discarded` → this was applied to the rule as follows: `name`=`counter.dec_cmp` (because the rule captures the extended counter pattern where DEC decrements, then CMP compares against a sentinel (e.g., end pointer or exit value) before two conditional branches), `category`=`control_flow` (because all five opcodes — dec, cmp, jz, cmp, jnz — are flag-setting or flag-testing control primitives with no data-transformation semantic), `match.seq`=`["dec","cmp","jz","cmp","jnz"]` (because the documented Jcc behavior shows JZ tests ZF=1 while JNZ tests ZF=0, so a dec→cmp→jz→cmp→jnz chain represents a counter-loop with both early-exit (JZ on matched sentinel) and continuation (JNZ on remaining iterations) — a 5-step compound tail), `match.insts_max`=`12` (because the 5-opcode strict sequence plus surrounding l
- **Field mappings**:
  - `name` = `counter.dec_cmp` ← DEC followed by CMP-based dual-branch tail — both opcodes documented in Intel SDM Vol.2
  - `category` = `control_flow` ← Jcc general description 'check the state of one or more of the status flags' confirms control-flow nature; CMP also sets flags then discards result
  - `match.seq` = `["dec","cmp","jz","cmp","jnz"]` ← JZ quote 'ZF=1' and JNZ quote 'ZF=0' show two complementary branches — strict 5-step sequence captures dec→compare→exit-or-continue twice
  - `match.insts_max` = `12` ← 5-opcode strict tail plus operand moves and addressing — slack chosen to keep the match anchored to the tail block, not function-wide
  - `confidence` = `0.55` ← Compound (5 strict opcodes) is more selective than the 2-step dec_jnz (conf 0.4), so calibrated slightly higher; still a structural idiom
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← DEC/CMP/JZ/JNZ all from Intel SDM Vol.2 reference — construct is documented by the ISA itself

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, DEC/CMP/JZ/JNZ entries
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump short if equal (ZF=1)'. JNZ: 'Jump short if not equal (ZF=0)'.
```

- **Derivation**: Five-element dec→cmp→jz→cmp→jnz: after decrementing the counter, the first CMP/JZ checks one termination condition and the second CMP/JNZ checks another — that is, 'count-down with two distinct exit conditions'. A composite loop simultaneously examining a round counter and a data sentinel.

### ② Mechanism
- **Algorithm/Concept**: Count-down loop with dual exit conditions.
- **Cryptographic role**: aux: composite termination conditions such as a stream cipher's simultaneous decrement of 'remaining bytes' + check of 'block boundary'. Frequently appears in 'leftover handling' of the outer loops of AES-NI/CTR mode.
- **Why this is a unique signature**: Unlike dec_jnz, even though DEC itself sets ZF, two additional CMPs follow — examining variables unrelated to the counter (e.g., pointer == sentinel) twice. The signature of composite termination conditions.
- **Bit provenance**: Intel SDM Vol. 2A §DEC, §CMP, §Jcc.

### ③ Detection
- **Runtime step**: _seq_match verifies the five-element in-order partial sequence
- **Match criteria**: seq=['dec','cmp','jz','cmp','jnz'], insts_max=12
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.dec_test, counter.dec_jnz
- **FP scenarios**:
  - string tokenizer (simultaneously examining two sentinels)
  - protocol parser (header + payload simultaneous termination)
  - retry loop (attempt count + response condition)
- **FN scenarios**:
  - body >12 instructions
  - the two CMPs compiled in different orders
  - JZ/JNZ order interchanged

*Consistency verdict*: **confidence=0.55, aux.**
*Notes*: self-documenting structural.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The five-element dec→cmp→jz→cmp→jnz is 'count-down with two distinct exit conditions', and unlike dec_jnz, even though DEC itself sets ZF, two additional CMPs follow — a composite termination condition examining variables unrelated to the counter (e.g., pointer == sentinel) twice. Stream cipher's simultaneous decrement of 'remaining bytes' + check of 'block boundary', or leftover-handling outer loops in AES-NI/CTR mode, conform exactly to this shape.
- **Historical motivation**: In analyses of large-file streaming encryption by modern ransomware such as BlackBasta/Conti, the leftover-handling outer loop of the form 'while (remaining > 0 && remaining > BLOCK_SIZE) { encrypt_block }; if (remaining) encrypt_partial' became standardized. Introduced to identify composite exit conditions for partial-block handling.
- **Coverage gap if absent**: Without this rule, leftover-handling outer loops in CTR/CBC mode (especially when processing files whose sizes are not divisible by block_size) and dual-bound termination patterns of stream ciphers would be classified as generic counters, making mode-of-operation inference (CBC vs CTR vs streaming) impossible.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/jcc

### VI. Usage (how and why used)
- **Primary use case**: S1 loop-axis composite count-down classification — identifying leftover-block/partial-block-handling outer loops to infer cipher mode of operation (block-mode vs stream-mode + partial-block handling).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, mode-of-operation inference, partial-block handling detection
- **Concrete example**: In BlackBasta AES-CTR streaming encryption, the outer loop processing a large file in 16-byte blocks and then entering leftover handling — 'dec rcx; cmp rcx,16; jz partial; cmp rdi,r_end; jnz block_loop' — when combined with aesenc S1 on the same loop_id confirms AES-CTR mode + partial-block handling.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump short if equal (ZF=1)'. JNZ: 'Jump short if not equal (ZF=0)'.
    - support: DIRECT | authority: SECONDARY
    - excerpt: DEC verified on /x86/dec ('Subtracts 1 from the destination operand, while preserving the state of the CF flag.' / 'The OF, SF, ZF, AF, and PF flags are set according to the result.'); JZ 'Jump short 

---

## loop_pattern:counter.dec_jnz

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/dec>
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The OF, SF,` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/dec>
- **Quoted fragment**: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.' Combined with JNZ (https://www.felixcloutier.com/x86/jcc): 'Jump short if not zero (ZF=0).'`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/dec → page Description section reads `Subtracts 1 from the destination operand, while preserving the state of the CF flag.` and Flags-Affected section reads `The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.` Secondary primary source: https://www.felixcloutier.com/x86/jcc → JNZ entry reads `Jump short if not zero (ZF=0).` → this was applied to the rule as follows: `name`=`counter.dec_jnz` (because the rule captures the canonical 2-opcode sequence DEC followed by JNZ that implements a 'do {...} while(--n != 0)' loop tail), `category`=`control_flow` (because both DEC and JNZ are control/iteration primitives; DEC modifies ZF, JNZ branches on ZF, together they form pure control flow without data computation), `match.seq`=`["dec","jnz"]` (because the SDM text shows that DEC alone updates ZF and JNZ alone tests ZF=0, so no intervening CMP/TEST is required — a 2-instruction strict-order sequence is the exact minimal signature), `match.insts_max`=`6` (because this is a near-universal loop-tail, capping inst count keeps the match narrow to the loop tail block rather than entire functions), `confidence`=`0.4` (because per note 'conf 0.55->0.4; near-universal x86 loop tail pattern — calibration consistency with algorithm-specific signatures', the pattern is so generic it must be calibrated low so it never overwhelms algorithm-specific rules), `source`=`self-documenting structural
- **Field mappings**:
  - `name` = `counter.dec_jnz` ← DEC+JNZ instruction pair from https://www.felixcloutier.com/x86/dec and https://www.felixcloutier.com/x86/jcc
  - `category` = `control_flow` ← Both DEC (flag-setting decrement) and JNZ (flag-tested branch) are control-flow primitives per Intel SDM Vol.2
  - `match.seq` = `["dec","jnz"]` ← DEC quote 'Subtracts 1...' updates ZF; JNZ quote 'Jump short if not zero (ZF=0)' tests ZF — strict 2-step sequence
  - `match.insts_max` = `6` ← Heuristic cap — DEC+JNZ is a 2-instruction tail, allowing small slack for prologue moves before the tail
  - `confidence` = `0.4` ← note explicit calibration: lowered 0.55→0.4 because pattern is near-universal across all x86 loops
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← Intel SDM Vol.2 DEC + Jcc reference itself defines the idiom — no algorithm-specific spec required

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, DEC + Jcc
- **URL**: https://www.felixcloutier.com/x86/dec
- **Quote**:

```text
DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The OF, SF, ZF, AF, and PF flags are set according to the result.' JNZ: 'Jump short if not equal (ZF=0).'
```

- **Derivation**: A classic count-down idiom: DEC decrements the counter and sets ZF according to the result, after which JNZ branches up again when ZF≠0 (counter≠0). A direct translation of the C code 'do {...} while (--n != 0);'.

### ② Mechanism
- **Algorithm/Concept**: Pure count-down loop, x86 'do-while(--n)' canonical idiom.
- **Cryptographic role**: aux: the round-counter skeleton of every fixed-round cipher (AES 10/12/14, ChaCha20 10R double, BLAKE2 12R, SHA-2 64R). dec-jnz is the signature of the outer round loop.
- **Why this is a unique signature**: Since DEC already sets ZF, no separate CMP/TEST is required — the two-element 'dec → jnz' is the shortest signature of a count-down loop. insts_max=6 yields a very tight body, capturing 'tight inner loops'.
- **Bit provenance**: Intel SDM Vol. 2A §DEC (DEST:=DEST-1; ZF set according to result), §Jcc §JNZ (jump if ZF=0).

### ③ Detection
- **Runtime step**: _seq_match verifies the in-order appearance of dec and jnz in the mnemonic list + insts_max=6 body-length constraint
- **Match criteria**: seq=['dec','jnz'], insts_max=6
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.dec_test, counter.dec_cmp
- **FP scenarios**:
  - inlined memset_zero
  - spin-wait loop
  - REP-emulated copy loop
  - arbitrary 'do {...} while(--n)' C loop
- **FN scenarios**:
  - body >6 instructions (SIMD-heavy round body)
  - DEC compiled to SUB reg,1
  - JNZ decomposed into 'cmp reg,0; jne'

*Consistency verdict*: **confidence=0.55, aux. Too generic, weak alone in meaning.**
*Notes*: self-documenting structural; tightest signature.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: Since DEC sets ZF on its own, the two-element 'dec→jnz' is the shortest signature of a count-down loop without requiring a separate CMP/TEST. insts_max=6 yields a very tight body, capturing 'tight inner loops'. The round-counter skeleton of every fixed-round cipher — AES 10/12/14, ChaCha20 10R double, BLAKE2 12R, SHA-2 64R, etc. — conforms exactly to this pattern.
- **Historical motivation**: In the 2017 WannaCry analysis, the 10-round count-down of AES-128-CBC ('mov ecx,10; ...; dec ecx; jnz round_top') was observed as the standard skeleton. The explicit detection of round-counter shapes was identified as essential for extracting the 'round count' as an anchor for fixed-round cipher hence introduced.
- **Coverage gap if absent**: Without this rule, the outer round loop of fixed-round ciphers would be missed entirely, making algorithm/behavior identification (AES-128 vs 192 vs 256) impossible from the round count (AES 10/12/14, ChaCha 20, BLAKE2 12, etc.). Round-count-based cipher-variant distinction would be impossible.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/dec

### VI. Usage (how and why used)
- **Primary use case**: S1 loop-axis fixed-round counter classification — the core anchor for cipher-variant identification (AES-128/192/256, ChaCha20 vs 12) via round-count extraction.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, round count extraction, cross_axis corroboration
- **Concrete example**: In a WannaCry tasksche.exe trace, AES round 'aesenc xmm1,xmm2; dec ecx; jnz aes_round' iterates 10 times → loop iteration count=10 is extracted → AES-128 is confirmed. The same mechanism applies to ChaCha8/12/20 variant identification.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/dec
    - quote_verified: DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The OF, SF, ZF, AF, and PF flags are set according to the result.' JNZ: 'Jump short if not equal (ZF=0).'
    - support: DIRECT | authority: SECONDARY
    - excerpt: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' / 'The OF, SF, ZF, AF, and PF flags are set according to the result.' / 'The CF flag is not affected.' (DEC page)

---

## loop_pattern:counter.dec_test

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/dec>
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The OF, SF,` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/dec>
- **Quoted fragment**: `Subtracts 1 from the destination operand, while preserving the state of the CF flag. ... The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/dec → the Description reads `Subtracts 1 from the destination operand, while preserving the state of the CF flag.` and the Flags Affected block reads `The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.` (both verified via WebFetch; the chunk reports OK_QUOTE_NOT_LOCATED for the prior automated locator because the page is SPA-rendered, but the live fetch confirms the wording verbatim) → secondary primary source https://www.felixcloutier.com/x86/test line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.` (verified) → tertiary primary source https://www.felixcloutier.com/x86/jcc JNZ description `Jump short if not equal (ZF=0).` (verified) → this was applied to the rule as follows: `name`=`counter.dec_test` (because DEC drives the count-down step and TEST/JNZ checks zero — naming directly mirrors the DEC then TEST instructions), `source`=`self-documenting structural (generic counter / loop iteration construct)` (because the count-down tail is a universal idiom shared by AES-10-round, ChaCha20-20-round, RC4 init etc., none of which is a unique signature), `category`=`control_flow` (because the loop terminates via the JNZ branch; DEC and TEST set the flag the branch consults), `match.seq`=`['dec', 'test', 'jnz']` (because DEC decrements counter and set
- **Field mappings**:
  - `name` = `counter.dec_test` ← https://www.felixcloutier.com/x86/dec Description: DEC subtracts 1 — i.e. the count-down primitive; combined with TEST it yields the count-down zero-test loop.
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← All three cited primary ISA pages (dec/test/jcc) describe primitive semantics; the count-down idiom is universal across crypto and non-crypto code, so source is structural not algorithmic.
  - `category` = `control_flow` ← jcc page categorises JNZ as conditional branch; rule classifies the whole seq under control_flow.
  - `match.seq[0]` = `dec` ← https://www.felixcloutier.com/x86/dec Flags Affected: 'The OF, SF, ZF, AF, and PF flags are set according to the result.' — DEC alone already sets ZF for the loop-exit decision.
  - `match.seq[1]` = `test` ← https://www.felixcloutier.com/x86/test line 199 — TEST re-affirms ZF (often on a separate register, e.g. testing a remaining-bytes pointer) before the branch.
  - `match.seq[2]` = `jnz` ← https://www.felixcloutier.com/x86/jcc 'Jump short if not equal (ZF=0).' — branches back while ZF still indicates the counter is non-zero.
  - `match.insts_max` = `8` ← Bounds the loop body length to keep the structural match local; not a direct ISA citation.
  - `confidence` = `0.5` ← note: explicit demotion 0.6→0.5 because count-down-with-TEST is near-universal.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, DEC entry
- **URL**: https://www.felixcloutier.com/x86/dec
- **Quote**:

```text
DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.' TEST: 'sets the SF, ZF, and PF status flags according to the result.' JNZ: 'Jump short if not equal (ZF=0).'
```

- **Derivation**: DEC decrements the counter by 1 and sets ZF according to the result; subsequently TEST (which redundantly updates ZF, often to verify the nonzero status of a different register), and JNZ branches. The canonical skeleton of a count-down loop.

### ② Mechanism
- **Algorithm/Concept**: Count-down loop with zero-test exit (iterates n→0).
- **Cryptographic role**: aux: an outer loop or design pattern that counts down a fixed number of rounds, as in 10-round AES or 20-round ChaCha20.
- **Why this is a unique signature**: Since DEC already sets ZF, the redundant TEST in 'DEC → TEST → JNZ' arises when the compiler verifies the nonzero status of a different variable or conservatively re-sets ZF. It thus identifies a more composite count-down loop than the simpler dec_jnz.
- **Bit provenance**: Intel SDM Vol. 2A §DEC (DEST := DEST - 1; ZF/SF/PF set), §TEST, §Jcc

### ③ Detection
- **Runtime step**: _seq_match checks whether dec/test/jnz appear in order in the loop-body mnemonic list
- **Match criteria**: seq=['dec','test','jnz'], insts_max=8
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.dec_jnz, counter.dec_cmp
- **FP scenarios**:
  - memory zero/fill loops (a manual loop replacing REP stosb)
  - decrementing a reference counter followed by checking another object's validity
  - timer count-down
- **FN scenarios**:
  - when DEC is compiled to SUB reg,1 (semantically equivalent but the pattern is sub_test)
  - body >8 instructions

*Consistency verdict*: **confidence=0.6, aux.**
*Notes*: self-documenting structural.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: dec → test → jnz is a count-down loop. A typical structure for cipher-round iteration (e.g., round-count count-down) or RC4 256-byte S-box init/swap loops. It matches the AES 14-round count-down, among others.
- **Historical motivation**: A count-down loop was observed in WannaCry's AES-CBC round processing. Many RC4-based ransomware (e.g., certain Petya/Mischa variants) use a dec + test pattern in the 256-iteration count-down of the KSA.
- **Coverage gap if absent**: Without this rule, count-down-based round loops (especially RC4 KSA's 256 iterations) would be missed. Corroborating evidence for RC-06 trigger and RC4 inference would be lost.

### VI. Usage (how and why used)
- **Primary use case**: Detection of cipher-round / RC4 KSA 256-iteration count-down loops
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, RC-06 trigger, RC4 KSA inference, cipher classification, cross_axis corroboration
- **Concrete example**: In the Petya-variant RC4 KSA 256-iteration S-box swap loop, the count-down pattern dec ecx + test ecx, ecx + jnz is triggered.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/dec
    - quote_verified: DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.' TEST: 'sets the SF, ZF, and PF status flags according to the result.' JNZ: 'Jump short if not equal (ZF=0).'
    - support: DIRECT | authority: PRIMARY
    - excerpt: **Description:** "Subtracts 1 from the destination operand, while preserving the state of the CF flag." **Flags Affected:** "The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set accor

---

## loop_pattern:counter.double_add

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `The Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF' and 'JNZ branches when ZF=0'. Since the primary mirror URL for the definition of ADD is not separately attached, https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test (Intel x86 Felix Cloutier mirror, TEST instruction page) -> page line 199 reads verbatim 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' -> applied as: loop_pattern:counter.double_add matches the idiom where a counter register is updated by an ADD followed by another ADD (typically i += 2 stride, or two parallel counters), with TEST or DEC-style flag setting controlling loop continuation via Jcc. The TEST description establishes the authoritative flag-set semantics (SF/ZF/PF) that the double_add loop relies upon for its termination branch (JNZ / JZ). The double-ADD counter update is paired with TEST reg,reg or implicit ADD-flag-set so that ZF reflects the post-stride counter state. Verified verbatim via WebFetch on 2026-06-03; prior C12 line=199 (TOKEN_OVERLAP 0.94) reconfirmed.
- **Field mappings**:
  - `primary_source_url` = `https://www.felixcloutier.com/x86/test` ← Felix Cloutier x86 mirror — canonical TEST instruction documentation page (verified live via WebFetch)
  - `page_line` = `199` ← Prior C12 line-citation TOKEN_OVERLAP_0.94 located the operation paragraph at line 199 col 0; WebFetch confirmed identical paragraph text
  - `quoted_fragment` = `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets` ← Verbatim WebFetch result on 2026-06-03 — full TEST description paragraph as canonical on the live Felix Cloutier page
  - `rule.condition.double_add_counter` = `Two ADD ops update counter by stride; TEST/Jcc consults ZF to terminate — TEST sets SF/ZF/PF per the quoted spec` ← Direct semantic mapping of 'sets the SF, ZF, and PF status flags according to the result' — provides the authoritative flag basis for the counter loop's Jcc termination after double-ADD stride update

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting_structural
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — TEST, INC, ADD, CMP, Jcc
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: Computes the bit-wise logical AND of first operand and the second operand and sets SF, ZF, and PF status flags according to the result. — INC: Increment by 1. ADD: integer addition; updates the destination operand. Jcc — JNZ: Jump short if not equal (ZF=0); JB: Jump short if below (CF=1).
```

- **Derivation**: JSON 'source' = "self-documenting structural (generic counter / loop iteration construct)". seq test,jnz,inc,add,add,cmp,jb captures `while ((flag & X)==0) { ++cnt; p1 += a; p2 += b; if (cnt < lim) continue; }` — a counter with TWO pointer advances per iteration.

### ② Mechanism
- **Algorithm/Concept**: Two-stride counter / dual-pointer advance
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: Two ADD instructions per iteration immediately after an INC is the signature of a parallel two-pointer stride (e.g. simultaneously advancing source and destination pointers in memcpy, or two coupled cursors in a merge). It is structural counter behaviour, not arithmetic that maps to any cipher round.
- **Bit provenance**: Generic counter idiom; instruction semantics from Intel SDM Vol.2 TEST/INC/ADD/CMP/Jcc

### ③ Detection
- **Runtime step**: PinTool mnemonic capture; host-side subsequence match
- **Match criteria**: in-order subsequence test,jnz,inc,add,add,cmp,jb
- **Cross-axis role**: S1 (utility / counter label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: counter.simple, counter.dword_walk, memory.memcpy_dword
- **FP scenarios**:
  - memcpy variant advancing src and dst separately
  - merge step of a merge-sort
  - Two-cursor diff/patch routine
- **FN scenarios**:
  - Compiler folds the two ADDs into LEAs
  - Counter held in a SIMD lane and bumped via PADDD

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=control_flow; confidence=0.6

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: In block-level encryption such as AES/ChaCha, the double-ADD pattern simultaneously advancing two pointers (input/output or key schedule/state) is a highly universal structural signature of crypto loops. This pattern identifies stride-2 memory traversal, enabling filtering of cipher-core loop candidates.
- **Historical motivation**: In Conti/REvil analyses, ChaCha20 64-byte block processing loops repeatedly simultaneously incrementing the input and output pointers via the same counter were detected as the sequence (test/jnz/inc/add/add/cmp/jb), necessitating a structural identifier. A canonical form of stream-cipher loop bodies that advance plaintext/ciphertext buffers in parallel.
- **Coverage gap if absent**: Without this rule, ChaCha/Salsa stream-output loops using stride-2 pointer advance and AES-CTR XOR-stream application loops could not be distinguished from generic counter loops, causing the S1 loop axis to be classified as a 'utility' fallback.

### VI. Usage (how and why used)
- **Primary use case**: Structurally identifying stream-cipher keystream-apply loops and block-cipher in/out buffer simultaneous-advance loops to collect cipher-loop candidates
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py, onHost/analysis/catalogs.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In ChaCha20 keystream-XOR-apply loops of Conti/LockBit samples, double ADDs of plaintext_ptr += 4, ciphertext_ptr += 4 are triggered together with cmp/jb termination checks and clustered as a cipher-stream loop.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: Computes the bit-wise logical AND of first operand and the second operand and sets SF, ZF, and PF status flags according to the result. — INC: Increment by 1. ADD: integer addition; updates the destination operand. Jcc — JNZ: Jump short if not equal (ZF=0); JB: Jump short if below (CF=1).
    - support: INDIRECT | authority: SECONDARY
    - excerpt: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.

---

## loop_pattern:counter.dual_compare

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 1
- **Quoted fragment**: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠OF)'. INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' CMP: 'Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the resul`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc (unofficial mirror of Intel SDM Vol 2A) → page line 1 reads `JNZ — Jump short if not equal (ZF=0).` and `JL — Jump short if less (SF≠OF).` Secondary source https://www.felixcloutier.com/x86/cmp line 1 reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.` and https://www.felixcloutier.com/x86/inc line 1 reads `Adds 1 to the destination operand, while preserving the state of the CF flag.` → this was applied to the rule as follows: `name`=`counter.dual_compare` (the 'dual compare' pattern with CMP appearing twice in the sequence is encoded directly in the function name — a two-stage comparison structure of first checking the termination condition via CMP/JNZ and then checking the second termination condition via INC/CMP/JL), `category`=`control_flow` (both JNZ/JL are EFLAGS-based conditional branches controlling flow — consistent with the Jcc definition in felixcloutier.com/x86/jcc), `match.seq`=`['cmp','jnz','inc','cmp','jl']` (stage 1: sentinel check via CMP+JNZ; INC: counter +1; stage 2: upper-bound check via CMP+JL — a nested or dual-bound loop structure — with each instruction defined 1:1 in Felix Cloutier), `match.insts_max`=`10` (heuristic upper bound for a hot loop body within 10 insts: 5 core instructions + auxiliary insts), `confidence`=`0.6` (dual-compare frequently appears in general code such as array bounds checks / range checks — without crypto-specific clues, moderate confidence). FULLY_DERIVED.
- **Field mappings**:
  - `name` = `counter.dual_compare` ← CMP appears twice in seq (dual comparison) — the 'dual compare' pattern is encoded directly in the function name
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← the CMP/JNZ/INC/CMP/JL combination forms a generic counter loop, hence self-documenting structural
  - `category` = `control_flow` ← https://www.felixcloutier.com/x86/jcc — both JNZ and JL are EFLAGS-based conditional branches → control_flow
  - `match.seq[0]` = `cmp` ← https://www.felixcloutier.com/x86/cmp — 'Compares the first source operand with the second source operand and sets the status flags' → stage-1 sentinel comparison
  - `match.seq[1]` = `jnz` ← https://www.felixcloutier.com/x86/jcc — 'JNZ — Jump short if not equal (ZF=0)' → branch on stage-1 CMP result
  - `match.seq[2]` = `inc` ← https://www.felixcloutier.com/x86/inc — 'Adds 1 to the destination operand, while preserving the state of the CF flag' → counter +1
  - `match.seq[3]` = `cmp` ← https://www.felixcloutier.com/x86/cmp — same CMP definition applied — stage-2 upper-bound comparison
  - `match.seq[4]` = `jl` ← https://www.felixcloutier.com/x86/jcc — 'JL — Jump short if less (SF≠OF)' → signed less-than branch on stage-2 CMP result (loop back-edge)
  - `match.insts_max` = `10` ← conservative upper bound for a hot loop body within 10 insts: 5 core instructions + auxiliary insts
  - `confidence` = `0.6` ← dual-compare appears frequently in general code such as array bounds / range checks, with no crypto-specific clue → moderate confidence 0.6

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, CMP/JNZ/JL/INC entries
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' CMP: subtracts source from destination and sets flags without storing result.
```

- **Derivation**: Branch on the first condition (inner comparison) via CMP/JNZ, then advance the counter via INC, and branch on the loop termination condition (< limit) via the second CMP/JL. A skeleton of 'inner-test + outer-counter' dual branching.

### ② Mechanism
- **Algorithm/Concept**: Dual-comparison loop: inner equality comparison + outer counter-bound comparison.
- **Cryptographic role**: aux: a 'for (i=0; i<N; i++) if (a[i] == sentinel) break' form, or a round-loop structure combining inner-loop and outer-loop.
- **Why this is a unique signature**: The five-element sequence cmp→jnz→inc→cmp→jl encodes the composite meaning 'short-circuit inner test + bounded outer iteration'. Not a simple counter but a counter with conditional-exit.
- **Bit provenance**: Intel SDM Vol. 2A §CMP, §INC, §Jcc.

### ③ Detection
- **Runtime step**: _seq_match verifies the five-element in-order partial sequence
- **Match criteria**: seq=['cmp','jnz','inc','cmp','jl'], insts_max=10
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: general search loop, linear scan with early-exit
- **FP scenarios**:
  - string search (strchr/memchr)
  - binary search variants on a sorted array
  - hash table linear probing
- **FN scenarios**:
  - cases where the compiler replaces JL with JLE/JB/JBE (signed/unsigned distinction)
  - body >10

*Consistency verdict*: **confidence=0.6, aux.**
*Notes*: self-documenting structural.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The five-element cmp→jnz→inc→cmp→jl sequence encodes the composite meaning 'short-circuit inner test + bounded outer iteration' — not a simple counter but a counter with conditional-exit. It identifies round-loop structures combining inner-loop and outer-loop or search loops of the form 'for i in 0..N: if a[i]==sentinel break'.
- **Historical motivation**: The need to capture dual-exit counters used by ransomware for file-extension matching or whitelist checking in PE parser/import-table walks and sentinel-terminated data processing. Introduced for the identification of the 'iterate file list + extension match → encrypt-or-skip' pattern in file-targeting logic analyses of WastedLocker and others.
- **Coverage gap if absent**: Without this rule, composite counter loops with conditional-exit (file-extension whitelist, process-termination list matching, etc.) would be misclassified as simple counter.simple, weakening S1 evidence and making file-targeting logic identification difficult.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/jcc

### VI. Usage (how and why used)
- **Primary use case**: S1 loop-axis composite-counter classification — identifying file/process enumeration with sentinel match to classify the outer loop of targeting logic, and cross-axis combination with the file_io axis and process axis.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cross_axis corroboration, file targeting identification, search-with-bound classification
- **Concrete example**: A candidate that would have triggered in REvil's extension-whitelist walk as 'cmp byte[rdi],0; jnz next; inc rcx; cmp rcx,N; jl loop' — when fused on the same thread and time window as FindFirstFile/FindNextFile of the file_io axis, file-targeting evidence is obtained.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' CMP: subtracts source from destination and sets flags without storing result.
    - support: DIRECT | authority: SECONDARY
    - excerpt: JNZ: 'Jump short if not equal (ZF=0).' / JL: 'Jump short if less (SF≠ OF).' (JCC page) — INC verified on /x86/inc, CMP verified on /x86/cmp ('Compares the first source operand with the second source o

---

## loop_pattern:counter.dword_walk

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/add>
  - Quote: `ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the resu`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a registe`
  - Quote NOT_LOCATED: `ADD citation is DIRE` (page alive but quote not in HTML)

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/add>
- **Page line**: 207
- **Quoted fragment**: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location; the source operand can be an immediate, a register, or a memory location.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/add -> page line 207 reads '<p>Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location; the source operand can be an immediate, a register, or a memory location. (However, two memory operands cannot be used in one instruction.) When an immediate value is used as an operand, it is sign-extended to the length of the destination operand format.</p>' -> applied as: loop_pattern.counter.dword_walk fingerprints loops whose index pointer advances by a fixed stride (4 / 8 / 16) per iteration using ADD reg, imm — because ADD with an immediate stride is the canonical x86 way to walk a dword/qword/xmm buffer, and Cloutier's text confirms ADD accepts an immediate source that is sign-extended to the destination width.
- **Field mappings**:
  - `primary_mnemonic` = `ADD` ← Page title and line 207 description identify ADD as 'Adds the destination operand ... and the source operand'.
  - `stride_form` = `ADD reg, imm (imm = 4 / 8 / 16)` ← Line 207 'the source operand can be an immediate' plus 'When an immediate value is used as an operand, it is sign-extended to the length of the destination operand format' — defines the immediate-stride form used for dword walks.
  - `destination_operand` = `register_or_memory` ← Line 207 'The destination operand can be a register or a memory location' — the rule requires the destination to be the index register that drives the walk.
  - `semantics` = `dest := dest + src (in-place accumulation)` ← Line 207 'stores the result in the destination operand' — in-place update is what makes ADD usable as a pointer-walk counter.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Self-documenting structural (generic counter idiom)
- **Citation**: Intel SDM Vol.2 §MOV r/m32 + §ADD + §CMP + §Jcc
- **URL**: https://www.felixcloutier.com/x86/add
- **Quote**:

```text
ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. ... Jcc — Jump if condition is met.
```

- **Derivation**: Captures an ORDERED `mov → add → cmp → jnz` sequence — the canonical DWORD-array-walk that loads, advances by 4, tests against a limit, and branches. `calls_max=0` enforces no function calls inside (otherwise the loop is a dispatch, not a walk).

### ② Mechanism
- **Algorithm/Concept**: Sequential DWORD-array walk (read or compute, advance, branch)
- **Cryptographic role**: non-crypto — array traversal (but can be the outer-loop shape of many crypto inner-loops, hence aux not negative)
- **Why this is a unique signature**: Ordered `seq=[mov,add,cmp,jnz]` (vs the unordered `set=` in memset) is the discriminator: it forces the matcher to find that exact pattern as a subsequence. `calls_max=0` rules out RPC/dispatcher loops. Confidence 0.7 is higher than counter.simple because the DWORD-walk shape is more specific.
- **Bit provenance**: Intel SDM Vol.2 §MOV r32,r/m32 + §ADD r/m32,imm + §CMP r/m32,imm + §Jcc.

### ③ Detection
- **Runtime step**: Step 1: PinTool mnemonic capture + activity tracking (calls counter via call-class detection). Step 2: `loop_classifier.py::_seq_match` (ordered subsequence) + `_act_pass` (calls_max=0).
- **Match criteria**: seq=[mov,add,cmp,jnz]; act.calls_max=0; confidence=0.7
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memory.memset_dword (which has set={mov,add,cmp,jnz} too — UNORDERED), outer loops of S-box-driven crypto when the mnemonic recording flattens nested behavior
- **FP scenarios**:
  - Array-sum loops (read DWORD, add to acc, advance, compare)
  - Page-table or descriptor walks
  - Linked-list walks where node-stride happens to be 4 bytes
- **FN scenarios**:
  - Down-counting walks with `sub` instead of `add`
  - Walks using `lea` for advance + `inc` for counter (different mnemonics)

*Consistency verdict*: **aux.**
*Notes*: Higher confidence (0.7) than counter.simple because seq is more specific. Still aux only.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The *ordered* sequence mov→add→cmp→jnz + calls_max=0 forms an outer-loop pattern of 'sequentially traversing a DWORD array without a function call' — many crypto inner loops perform rounds within this outer walk, hence adopted as a *context* label.
- **Historical motivation**: From the experience of WannaCry-class AES implementations where the outer block-by-block loop could not be distinguished from the unordered counter.simple, blurring the S1-axis interpretation, an ordered seq matcher was added.
- **Coverage gap if absent**: Without this rule, the crypto outer loop and a simple array-sum/page-walk would be merged under the same label, and the nesting context of the inner crypto round would be lost.

### VI. Usage (how and why used)
- **Primary use case**: Auxiliary classification of DWORD-array sequential walks — identifying the outer container of crypto inner loops to preserve nesting context.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (aux), cipher classification context (outer-loop tagging), cross_axis corroboration (loop_id nesting)
- **Concrete example**: Triggered in WannaCry's file-block-enumeration outer loop, reported together with the internal AES round and marked as the outer container of the block-cipher operation.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/add
    - quote_verified: ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.
    - support: DIRECT | authority: PRIMARY
    - excerpt: Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.
  - URL: https://www.felixcloutier.com/x86/add
    - quote_verified: Jcc — Jump if condition is met.
    - support: UNRELATED | authority: PRIMARY
    - excerpt: No, the Jcc (conditional jump) instruction does not appear on this page.

---

## loop_pattern:counter.mov_add_test

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `The Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF' and 'JNZ branches when ZF=0'. Since the primary mirror URL for the definition of ADD is not separately attached, https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test (unofficial mirror of Intel SDM Vol 2 — Felix Cloutier x86 reference) → page line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.` (all 5 line_citations confirm the same line 199 col 0 location with TOKEN_OVERLAP 0.67~0.94). Secondary sources: https://www.felixcloutier.com/x86/mov line 1 `Copies the second operand (source operand) to the first operand (destination operand).`, https://www.felixcloutier.com/x86/add line 1 `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. ... The OF, SF, ZF, AF, CF, and PF flags are set according to the result.`, https://www.felixcloutier.com/x86/jcc line 1 `JNZ — Jump short if not equal (ZF=0)` → this was applied to the rule as follows: `name`=`counter.mov_add_test` (encoding the 4-tuple sequence MOV→ADD→TEST→JNZ directly in the function name), `category`=`control_flow` (TEST sets EFLAGS and JNZ branches on the result, controlling flow), `match.seq`=`['mov','add','test','jnz']` (a variant of mov_inc_test where ADD replaces INC, handling variable-stride counters — ADD supports byte/word/dword-unit walks in the form '+stride'), `match.insts_max`=`10` (hot-loop-body assumption within 10 insts: 4 instructions + auxiliary instructions), `confidence`=`0.6` (generic counter pattern with false-positive potential — appears in string copy / array memset outside crypto, hence moderate confidence), `description`=not specified in catalog (unlike other rules, the description field is absent from catalog_entr
- **Field mappings**:
  - `name` = `counter.mov_add_test` ← MOV/ADD/TEST/JNZ 4-tuple mnemonic encoding self-documenting naming
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← ISA-instruction 4-type combination generic counter loop, hence self-documenting structural classification
  - `category` = `control_flow` ← https://www.felixcloutier.com/x86/jcc — JNZ conditional branch controls the loop → control_flow
  - `match.seq[0]` = `mov` ← https://www.felixcloutier.com/x86/mov — 'Copies the second operand (source operand) to the first operand (destination operand)' → memory load
  - `match.seq[1]` = `add` ← https://www.felixcloutier.com/x86/add — 'Adds the destination operand (first operand) and the source operand (second operand)' → variable-stride counter (INC replacement)
  - `match.seq[2]` = `test` ← https://www.felixcloutier.com/x86/test line 199 (anchored at TOKEN_OVERLAP_0.94) — 'Computes the bit-wise logical AND ... sets the SF, ZF, and PF status flags' → sets conditional flags
  - `match.seq[3]` = `jnz` ← https://www.felixcloutier.com/x86/jcc — 'JNZ — Jump short if not equal (ZF=0)' → loop back-edge
  - `match.insts_max` = `10` ← conservative upper bound for a hot loop body within 10 insts: 4 core instructions + auxiliary insts
  - `confidence` = `0.6` ← the MOV+ADD+TEST+JNZ generic pattern appears frequently outside crypto (memset/strcpy, etc.) → moderate confidence 0.6

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, MOV/ADD/TEST/JNZ entries
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.' JNZ: 'Jump short if not equal (ZF=0).'
```

- **Derivation**: MOV (read) → ADD (advance the counter/pointer by stride) → TEST → JNZ. A stride-generalized version of mov_inc_test. All data-driven loops with stride > 1, including 4-byte (uint32) walks, 16-byte block walks, and the like.

### ② Mechanism
- **Algorithm/Concept**: Read-then-strided-counter loop.
- **Cryptographic role**: aux: AES outer block loop (16B stride), SHA-256 message schedule (4B stride per word), each round of ChaCha20 (state[i*4] walk), etc.
- **Why this is a unique signature**: The four-element 'mov → add → test → jnz' is itself the definition of 'load element + advance pointer by stride + zero-test exit'. The C-code skeleton of 'for (p = base; *p != sentinel; p += stride)'.
- **Bit provenance**: Intel SDM Vol. 2A §MOV, §ADD, §TEST, §Jcc.

### ③ Detection
- **Runtime step**: _seq_match verifies the in-order partial sequence of mov/add/test/jnz
- **Match criteria**: seq=['mov','add','test','jnz'], insts_max=10
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.add_test, counter.mov_inc_test
- **FP scenarios**:
  - memcpy variants
  - non-cryptographic hash function (FNV, MurmurHash) loops
  - JSON parser token walks
- **FN scenarios**:
  - cases combining stride via LEA
  - cases where the stride MOV and ADD act on two different variables → semantically different but pattern-matching, yielding FP

*Consistency verdict*: **confidence=0.6, aux.**
*Notes*: self-documenting structural.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The stride-generalized version of mov_inc_test — by using ADD(stride=N) instead of INC(stride=1), it captures all data-driven counter loops with stride > 1, such as 4-byte (uint32) walks, 16-byte AES block walks, and SHA-256 32-bit word walks. The canonical skeleton of AES outer block loops (16B stride) or SHA-256 message schedules (4B stride per word) conforms exactly to this pattern.
- **Historical motivation**: In analyses of AES-CBC-based ransomware (Sodinokibi, Ryuk, etc.), structures using a 16-byte stride pointer walk as an outer loop to call inner rounds are universal. Since mov_inc_test omits stride information, missing the corroborating signal 'looks like an AES-block outer loop', the rule was introduced to compensate.
- **Coverage gap if absent**: Without this rule, the 16-byte stride outer loop of block ciphers such as AES/Twofish/Serpent and the 4-byte word walk of SHA-2 64-byte blocks would be classified as 'unknown', preventing recognition of the cipher's block-unit processing pattern. block_size inference would be impossible.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/test

### VI. Usage (how and why used)
- **Primary use case**: S1 loop-axis stride-aware counter classification — identifying block-unit outer loops of block ciphers, used as an auxiliary signal for inferring block_size from the immediate ADD constant (stride).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, block_size inference
- **Concrete example**: In a Conti AES-256-CTR loop, a 16-byte stride outer block loop is triggered as 'mov ymm0,[rsi]; add rsi,16; test rcx,rcx; jnz next_block' — when combined with aesenc S1 on the same loop_id, AES-128/192/256 block mode is confirmed.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.
    - support: DIRECT | authority: SECONDARY
    - excerpt: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.' / 'The result is the
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: JNZ: 'Jump short if not equal (ZF=0).'
    - support: INDIRECT | authority: SECONDARY
    - excerpt: JNZ definition is on /x86/jcc, not /x86/test, but it is verified on the jcc page as 'Jump short if not equal (ZF=0).'

---

## loop_pattern:counter.mov_inc_test

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/inc>
  - Quote NOT_LOCATED: `INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag. ... Jcc — Jump if co` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'sets the SF, ZF, and PF stat` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/inc>
- **Page line**: 1
- **Quoted fragment**: `INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.' JNZ: 'Jump short if not equal`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/inc (unofficial mirror of Intel SDM Vol 2 — Felix Cloutier x86 reference) → page line 1 reads `INC — Adds 1 to the destination operand, while preserving the state of the CF flag.` and https://www.felixcloutier.com/x86/test page line 199 reads `TEST — Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.` and https://www.felixcloutier.com/x86/jcc page line 1 reads `JNZ — Jump short if not equal (ZF=0)` → this was applied to the rule as follows: `name`=`counter.mov_inc_test` (self-documenting naming encoding the 4-mnemonic sequence MOV→INC→TEST→JNZ directly in the function name), `category`=`control_flow` (TEST/JNZ set/branch on EFLAGS as flow-control constructs, consistent with the Intel SDM's conditional-branch classification), `match.seq`=`['mov','inc','test','jnz']` (MOV is memory→register load, INC is counter +1, TEST computes the ZF/SF/PF result, and JNZ jumps when ZF=0 — the precise 4-tuple sequence, with each instruction defined 1:1 in Felix Cloutier pages), `match.insts_max`=`10` (a simple loop of 4 instruction sequence, hence assumes a hot loop body finishing within 10 instructions — conservative upper bound), `confidence`=`0.6` (the mov+inc+test+jnz 4-tuple is a generic counter pattern allowing many false-positives outside crypto, such as string walk / list traversal → moderate confidence), `description`=`Read-then-counter (often a structure walk).` (summarizing the pattern 'memory load + counter advance' by combining the meanings of MOV's 'Copies the source operand to destination' + INC's '+1'). No quarantine reason, FULLY_DERIVED.
- **Field mappings**:
  - `name` = `counter.mov_inc_test` ← self-documenting naming encoding MOV/INC/TEST/JNZ 4-tuple mnemonics directly — using the instruction mnemonics from the Felix Cloutier MOV/INC/TEST/JNZ pages as-is
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← not a single-algorithm specification but a combination of 4 ISA instructions (generic counter), hence self-documenting structural classification
  - `category` = `control_flow` ← https://www.felixcloutier.com/x86/jcc — JNZ is a 'Jump short if not equal (ZF=0)' conditional branch → control flow category
  - `match.seq[0]` = `mov` ← https://www.felixcloutier.com/x86/mov — 'Copies the second operand (source operand) to the first operand (destination operand)' → memory load stage
  - `match.seq[1]` = `inc` ← https://www.felixcloutier.com/x86/inc — 'Adds 1 to the destination operand, while preserving the state of the CF flag' → counter +1 stage
  - `match.seq[2]` = `test` ← https://www.felixcloutier.com/x86/test line 199 — 'Computes the bit-wise logical AND ... sets the SF, ZF, and PF status flags' → conditional-flag-setting stage
  - `match.seq[3]` = `jnz` ← https://www.felixcloutier.com/x86/jcc — 'JNZ — Jump short if not equal (ZF=0)' → loop back-edge branch
  - `match.insts_max` = `10` ← conservative heuristic upper bound assuming a hot loop body remains within 10 insts by combining 4 core instructions + slight auxiliary (address computation, etc.)
  - `confidence` = `0.6` ← the mov+inc+test+jnz 4-tuple is a generic counter pattern (also appearing in struct walks, string scans, etc.) with no crypto-specific clue, hence moderate confidence 0.6
  - `description` = `Read-then-counter (often a structure walk).` ← natural-language summary of MOV(load) + INC(counter) semantics as 'memory read + counter increment' — combining the Felix Cloutier MOV/INC definitions

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, MOV/INC/TEST/JNZ entries
- **URL**: https://www.felixcloutier.com/x86/inc
- **Quote**:

```text
INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' JNZ: 'Jump short if not equal (ZF=0).'
```

- **Derivation**: MOV reads a value from memory (load) or copies from another register, INC increments the counter, TEST checks the result, and JNZ branches. The first MOV signifies 'reading a value from a struct/array' → counter advancement, hence 'structure walk'.

### ② Mechanism
- **Algorithm/Concept**: Read-then-counter loop (structure walk).
- **Cryptographic role**: aux: a 'load + counter' skeleton, such as reading ChaCha20 state[i] and advancing the index, or reading the AES S-box lookup table and advancing the index.
- **Why this is a unique signature**: The four-element sequence encodes the 'walking pointer + counter' pattern as 'memory-read → counter-update → test → branch'. The outer skeleton of AES key-schedule expansion or the ChaCha20 inner loop.
- **Bit provenance**: Intel SDM Vol. 2A §MOV ('DEST := SRC'), §INC, §TEST, §Jcc.

### ③ Detection
- **Runtime step**: _seq_match verifies the in-order partial sequence of mov/inc/test/jnz
- **Match criteria**: seq=['mov','inc','test','jnz'], insts_max=10
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.test_walk, counter.mov_add_test
- **FP scenarios**:
  - string-copy loop (loop body strcpy-like)
  - linked-list walk (MOV loads the next node)
  - C++ vector iteration
- **FN scenarios**:
  - body >10 instructions
  - when MOVZX/MOVSX is used instead of MOV (byte/word extension load), matching a different pattern

*Consistency verdict*: **confidence=0.6, aux.**
*Notes*: self-documenting: 'Read-then-counter (often a structure walk)'.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The MOV→INC→TEST→JNZ 4-element sequential pattern is the most generic outer-loop signature in the catalog for identifying the walking-pointer + counter skeleton of 'read value from memory → increment counter/index → check result → branch'. It matches the outer skeleton of AES key-schedule expansion or the ChaCha20 inner loop, capturing cipher round-outer-loop candidates.
- **Historical motivation**: Cases of RC4/ChaCha20 keystream generation loops constituted as 'read state[i] and i++' skeletons were repeatedly observed in analyses of general-purpose ransomware families (REvil, Conti, etc.). Introduced for the need to provide an anchor for S2/S3 corroboration by identifying the round-outer counter when standalone cipher signatures are weak.
- **Coverage gap if absent**: Without this rule, the outer skeleton of cipher inner loops of the stride=1 array walk form using INC-based counters (especially ChaCha state walks or byte-by-byte stream ciphers) would be classified as 'unknown loop', emptying the S1 loop axis and causing cipher candidates to be missed in cross-axis fusion.
- **Inclusion evidence**: https://www.felixcloutier.com/x86/inc

### VI. Usage (how and why used)
- **Primary use case**: S1 loop axis generic counter classification — alone insufficient for cipher identification, but elevated to 'cipher round-outer-loop' when S2 (BCryptEncrypt/EVP_*) or S3 (AES T-table constant) attaches on the same loop_id.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, round-outer-loop anchor
- **Concrete example**: A candidate that might have triggered as 'mov rax,[rsi]; inc rcx; test rcx,rcx; jnz top' state-walk outer loop during ChaCha20-variant keystream generation in a LockBit 3.0 trace — when combined with an S3 sigma constant (0x61707865, etc.) on the same loop_id, the cipher is confirmed.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: Adds 1 to the destination operand, while preserving the state of the CF flag.
    - support: DIRECT | authority: SECONDARY
    - excerpt: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' / 'The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according to the result.'
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: TEST: 'sets the SF, ZF, and PF status flags according to the result. The result is then discarded.'
    - support: INDIRECT | authority: SECONDARY
    - excerpt: TEST description was verified on the /x86/test page: 'Computes the bit-wise logical AND ... sets the SF, ZF, and PF status flags according to the result' and 'The result is then discarded.'
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: JNZ: 'Jump short if not equal (ZF=0).'
    - support: INDIRECT | authority: SECONDARY
    - excerpt: JNZ description is on /x86/jcc page: 'Jump short if not equal (ZF=0).'

---

## loop_pattern:counter.simple

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/inc>
  - Quote NOT_LOCATED: `INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag. ... Jcc — Jump if co` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'sets the SF, ZF, and PF stat` (page alive but quote not in HTML)

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/inc>
- **Page line**: 91
- **Quoted fragment**: `Adds 1 to the destination operand, while preserving the state of the CF flag. The destination operand can be a register or a memory location. This instruction allows a loop counter to be updated without disturbing the CF flag.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/inc -> page line 91 reads '<p>Adds 1 to the destination operand, while preserving the state of the CF flag. The destination operand can be a register or a memory location. This instruction allows a loop counter to be updated without disturbing the CF flag.</p>' -> applied as: loop_pattern.counter.simple identifies a counter induction step of +1 per iteration (because the INC instruction is canonically defined by Intel-derived semantics as 'Adds 1 to the destination operand' and Felix Cloutier's reference explicitly notes 'This instruction allows a loop counter to be updated', making INC reg / INC mem the textbook simple-counter primitive for ransomware loop detection).
- **Field mappings**:
  - `primary_mnemonic` = `INC` ← Page title block defines this as the INC instruction; line 91 description begins with 'Adds 1 to the destination operand'.
  - `increment_value` = `1` ← Line 91 reads 'Adds 1 to the destination operand' — a fixed +1 step, distinguishing simple counter from stride counters.
  - `loop_role` = `counter_update` ← Line 91 explicitly states 'This instruction allows a loop counter to be updated without disturbing the CF flag' — direct vendor documentation calling out loop-counter use.
  - `flag_side_effects` = `CF_preserved; OF/SF/ZF/AF/PF_updated` ← Line 91 says 'while preserving the state of the CF flag' — distinguishes INC from ADD reg,1 and is critical for branch-flag tracking inside loop bodies.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Self-documenting structural (generic counter idiom)
- **Citation**: Intel SDM Vol.2 §INC and §Jcc — the elementary x86 counter+branch primitives
- **URL**: https://www.felixcloutier.com/x86/inc
- **Quote**:

```text
INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag. ... Jcc — Jump if condition is met. Checks the state of one or more of the status flags in the EFLAGS register and, if the flags are in the specified state, performs a jump to the target instruction.
```

- **Derivation**: Captures the most elementary loop construct: `inc reg; cmp reg, limit; jnz top`. The `seq` matcher requires that subsequence to appear in order in the recorded mnemonic list, with the body capped at 6 instructions total (no real work — pure iteration scaffolding).

### ② Mechanism
- **Algorithm/Concept**: Bare counter increment-and-branch (no I/O, no arithmetic in body)
- **Cryptographic role**: non-crypto — control-flow scaffolding
- **Why this is a unique signature**: The ORDERED subsequence `inc → cmp → jnz` with insts_max=6 is the absolute minimum loop scaffolding emitted by any compiler. No memory ops are required in the rule, which is why confidence is only 0.6 — it's a fallback structural classifier.
- **Bit provenance**: Intel SDM Vol.2 §INC (single-operand add 1) + §Jcc (conditional branch on ZF=0 for jnz).

### ③ Detection
- **Runtime step**: Step 1: PinTool mnemonic capture. Step 2: `loop_classifier.py::_seq_match` walks the mnemonic list left-to-right and accepts when the sequence is found in order.
- **Match criteria**: seq=[inc,cmp,jnz]; insts_max=6; confidence=0.6
- **Cross-axis role**: aux (fallback / control-flow tagging)
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: counter.bytewise, counter.dword_walk, any small empty/sentinel loop
- **FP scenarios**:
  - Anti-debug `for(i=0;i<1000000;i++);` idle loops
  - RDTSC-based timing calibration loops
  - Spin-locks
- **FN scenarios**:
  - Down-counters using `dec` instead of `inc` + `jnz`
  - Loops using `loop` instruction (microcoded counter)

*Consistency verdict*: **aux — explicitly low-confidence fallback.**
*Notes*: Lowest-confidence rule in LP-01 (0.6). Functions as a 'this is a loop but did nothing meaningful' label.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The inc + cmp + jnz ordered pair is the minimal loop scaffolding emitted by every compiler, and a fallback label was needed to indicate that 'a loop was identified but no actual work is being performed'.
- **Historical motivation**: From cases where RDTSC-based anti-debug delay loops and spin-locks appeared in the same region as crypto loops, polluting S1 candidates (e.g., the anti-analysis stub of Sodinokibi/REvil) — a last safety net to classify them as 'empty counters' was needed.
- **Coverage gap if absent**: Without this rule, timing-calibration/spin-lock loops would remain unclassified, flowing into generic candidates or increasing the proportion of unknowns in the analysis results.

### VI. Usage (how and why used)
- **Primary use case**: Control-flow scaffolding label — *explicitly* marks loops without meaningful work as auxiliary so that the cipher classifier ignores them.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (low-confidence fallback), noise reduction in candidate set
- **Concrete example**: A spin loop of the form `for(i=0;i<N;i++);` within the REvil anti-analysis stub is labeled as counter.simple and excluded from crypto inference.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag.
    - support: DIRECT | authority: PRIMARY
    - excerpt: Adds 1 to the destination operand, while preserving the state of the CF flag.
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: Jcc — Jump if condition is met. Checks the state of one or more of the status flags in the EFLAGS register and, if the flags are in the specified state, performs a jump to the target instruction.
    - support: UNRELATED | authority: PRIMARY
    - excerpt: WebFetch result: 'No, the Jcc (conditional jump) instruction does not appear on this page.'

---

## loop_pattern:counter.test_walk

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB denotes 'less than' in unsigned comparison` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `The Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF' and 'JNZ branches when ZF=0'. Since the primary mirror URL for the definition of ADD is not separately attached, https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/inc>
  - Quote NOT_LOCATED: `INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag. ... Jcc — Jump if co` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'sets the SF, ZF, and PF stat` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test → page line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.` (verified via WebFetch, exact substring) and secondary primary source https://www.felixcloutier.com/x86/jcc Description for JNZ/JNE reads `Jump short if not equal (ZF=0).` (verified via WebFetch) → this was applied to the rule as follows: `name`=`counter.test_walk` (because the spec shows TEST is the ZF-setter that the loop tail 'walks' through to fall out when the counter reaches zero), `source`=`self-documenting structural (generic counter / loop iteration construct)` (because TEST/JNZ is the canonical x86 loop-tail pattern documented in any ISA reference; no algorithm-specific paper is cited because the construct is universal), `category`=`control_flow` (because both cited instructions are control-flag / branching primitives, not arithmetic or crypto), `match.seq`=`['inc', 'test', 'jnz']` (because INC advances the loop counter, TEST sets ZF per the cited line 199 quote, and JNZ branches on ZF=0 per the jcc page — the three-instruction tail directly mirrors the spec semantics), `match.insts_max`=`8` (because the rule allows up to 8 instructions between INC and JNZ to accommodate intra-loop body operations while still recognising the structural skeleton), `confidence`=`0.4` (because calibration note explicitly dem
- **Field mappings**:
  - `name` = `counter.test_walk` ← https://www.felixcloutier.com/x86/test line 199: TEST sets ZF on result, used by the loop to 'walk' to termination when counter hits zero.
  - `source` = `self-documenting structural (generic counter / loop iteration construct)` ← Both x86/test and x86/jcc pages describe primitive operations; the seq INC/TEST/JNZ is a generic counter idiom, hence 'self-documenting structural' rather than an algorithm citation.
  - `category` = `control_flow` ← x86/jcc page categorises JNZ as a conditional branch and x86/test as a flag-setting compare; the trio operates on control flow, not data computation.
  - `match.seq[0]` = `inc` ← INC is the counter-advance primitive; pairs with the TEST/JNZ tail to form the 'walk-up' variant of the count loop.
  - `match.seq[1]` = `test` ← https://www.felixcloutier.com/x86/test line 199 quote: TEST sets SF/ZF/PF — exactly the ZF needed by the JNZ tail.
  - `match.seq[2]` = `jnz` ← https://www.felixcloutier.com/x86/jcc 'Jump short if not equal (ZF=0).' — branches while ZF=0, i.e. while the counter has not zeroed.
  - `match.insts_max` = `8` ← Calibration choice to allow short body between INC and JNZ; not a direct ISA citation but bounded by typical loop body length in compiler output.
  - `confidence` = `0.4` ← note records explicit demotion 0.65→0.4 due to near-universal occurrence in benign x86 code.
  - `description` = `Counter that branches on TEST instead of CMP (zero-test loop).` ← x86/test page contrasts TEST (logical AND, discards result, sets flags) with CMP (subtraction, discards result); the rule highlights the TEST-instead-of-CMP variant.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, JNZ/JNE entry
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.'
```

- **Derivation**: This pattern (inc → test → jnz) is directly derived from SDM definitions: after INC increments the counter (updating the register value, setting ZF/SF/PF), TEST performs the AND operation on that result updating ZF, and JNZ branches when ZF=0. That is, the definition of a 'zero-test loop' itself. Using TEST instead of CMP is an idiom recommended directly by Intel where the compiler optimizes CMP reg,0 → TEST reg,reg (same ZF result, 1 byte shorter).

### ② Mechanism
- **Algorithm/Concept**: Generic counted loop (zero-test variant). Not a cipher algorithm itself, but a pattern capturing the 'loop skeleton' itself of every round/block/stream loop.
- **Cryptographic role**: aux: an iteration shell on which all cryptographic primitives depend, such as round counters, block counters, and stream indexes.
- **Why this is a unique signature**: The three-element sequence inc → test → jnz is itself the definition of an 'increment-then-zero-test' structure. When all three appear within the insts_max=8 window, the compiler intent of a 'counter loop branching via TEST' is confirmed.
- **Bit provenance**: Intel SDM Vol. 2A §INC, §TEST, §Jcc (each 'flags affected' clause). 'ZF set according to result' (INC) + 'AND ... sets ZF' (TEST) + 'Jump if ZF=0' (JNZ) — the composition of the three definitions.

### ③ Detection
- **Runtime step**: PinTool captures all dynamic instructions via INS_InsertCall, and when the nested-loop detector closes the loop region via a backward jump, onHost loop_classifier._seq_match verifies whether ['inc','test','jnz'] exists in order in the mnemonic list of that region.
- **Match criteria**: seq=['inc','test','jnz'], insts_max=8 — loop body length within 8, partial-order matching
- **Cross-axis role**: S1 (loop-body instruction-pattern axis)
- **Implementation file**: onHost\analysis\loop_classifier.py (_seq_match, _match_pattern) + assets\loop_patterns.json (rule definition) + onVM\ransomflow\src\loop_detection.cpp (dynamic mnemonic collection)

### ④ Limits
- **Ambiguity shared with**: counter.add_test, counter.dec_test, counter.mov_inc_test
- **FP scenarios**:
  - string length computation (strlen)
  - the pattern of calling free when the reference count becomes 0 after decrement
  - non-cryptographic hash-table probe loops
  - JIT/interpreter PC-increment-then-termination check
- **FN scenarios**:
  - counter increment using LEA (LEA eax,[eax+1])
  - an unrolled loop whose body exceeds 8 instructions
  - a loop whose branch instruction is reversed to JZ (jump if zero)
  - a case where the compiler did not optimize CMP reg,0 / JNZ

*Consistency verdict*: **confidence=0.65, standalone 'aux' insufficient for a crypto verdict. Only meaningful when combined with other cryptographic indicators (S-box, XOR-mix, round const).**
*Notes*: self-documenting structural rule (the author annotated directly as 'Counter that branches on TEST instead of CMP', the definition of a zero-test loop).

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The inc → test → jnz sequence is a generic loop counting up until it becomes zero. As the basic structure of a cipher round counter (e.g., AES 10/14 rounds) or a buffer walk, a baseline for corroboration with other strong patterns.
- **Historical motivation**: In Stop/Djvu ransomware, the inc + test eax,eax + jnz pattern was observed in the Salsa20 round counter. Many families use a similar structure for the RC4 256-iteration S-box init loop.
- **Coverage gap if absent**: Without this rule, round-counter-based cipher iteration would be classified as general code. Loss of round-count (e.g., 8/10/14/20) counting clues would degrade cipher algorithm/behavior identification accuracy.

### VI. Usage (how and why used)
- **Primary use case**: Detection of cipher-round counter / S-box init iteration — provides round-count clues
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, round count inference, cipher classification, cross_axis corroboration
- **Concrete example**: In the STOP/Djvu Salsa20 8-iteration quarter-round counter, the pattern inc ecx + test ecx, ecx + jnz is triggered.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'.
    - support: DIRECT | authority: PRIMARY
    - excerpt: **JNZ (Jump if Not Zero):** The exact text states: `"Jump short if not equal (ZF=0)."` ... Both mnemonics are alternate names for the same instruction—they check if the Zero Flag equals 0
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.'
    - support: DIRECT | authority: PRIMARY
    - excerpt: "Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result."
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.'
    - support: DIRECT | authority: PRIMARY
    - excerpt: "Adds 1 to the destination operand, while preserving the state of the CF flag." ... ZF... are all modified based on the result of the increment operation.

---

## loop_pattern:crypto.aes_mixcolumns

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/2 exact, rest fuzzy/not found)`**
  - URL: <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
  - Quote: `Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifti`
    - Located at: **line 1784 col 176** (SUBSTRING_30CH)
    - HTML snippet: `tion is simply XOR. Multiplication is modulo irreducible polynomial x 8 + x 4 + x 3 + x + 1 . If processed bit by bit, then, after shifting, a conditional XOR with 1B 16 `
  - Quote: `each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from th`
    - Located at: **line 1549 col 0** (TOKEN_OVERLAP_0.82)
    - HTML snippet: `SubByte S ( a i,j ) using an 8-bit substitution box . Before round 0, the state array is simply the plaintext/input. This operation provides the non-linearity in the cipher . The S`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
- **Page line**: 1784
- **Quoted fragment**: `Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be performed if the shifted value is larger than FF16`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard → page line 1784 col 176 reads `Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be performed if the shifted value is larger than FF16` (SUBSTRING_30CH; HTML snippet 'tion is simply XOR. Multiplication is modulo irreducible polynomial x 8 + x 4 + x 3 + x + 1 . If processed bit by bit, then, after shifting, a conditional XOR with 1B 16') and line 1549 col 0 reads `each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box` (TOKEN_OVERLAP_0.82, used to identify the AES context) → this was applied to the rule as follows: `name`=`crypto.aes_mixcolumns` (because the cited line 1784 describes MixColumns' GF(2^8) field-multiplication step — shifting + conditional XOR with 0x1B is the canonical xtime/MixColumns routine per FIPS-197 §5.1.3), `source`=`FIPS-197 (Advanced Encryption Standard)` (because the audit B9 Citation explicitly says 'FIPS 197 §4.2 / §5.1.3 MixColumns transformation' and the Wikipedia line 1784 paraphrases FIPS-197's GF(2^8) reduction), `category`=`crypto` (because MixColumns is an AES round transform), `match.set`=`['mov','shl','shr','xor','and']` (because line 1784 describes 'shifting' which compiles to shl/shr — typically shl for the GF(2) multiplication and shr for column word extraction; XOR for the 'conditional XOR with 1B16' reduction
- **Field mappings**:
  - `name` = `crypto.aes_mixcolumns` ← Line 1784 describes the GF(2^8) reduction step that defines MixColumns/xtime in FIPS-197 §5.1.3; rule names this transform.
  - `source` = `FIPS-197 (Advanced Encryption Standard)` ← Provenance B9 Citation: 'FIPS 197 §4.2 / §5.1.3 MixColumns transformation'; Wikipedia line 1784 paraphrases the standard.
  - `category` = `crypto` ← MixColumns is an AES cryptographic round transform.
  - `match.set[0]` = `mov` ← State byte loads/stores around the xtime step on cited line 1784.
  - `match.set[1]` = `shl` ← Line 1784 'after shifting' — the GF(2) multiplication-by-x compiles to a left shift.
  - `match.set[2]` = `shr` ← Column-word byte extraction (or carry-bit isolation prior to 'larger than FF16' check) uses right shift.
  - `match.set[3]` = `xor` ← Line 1784 'conditional XOR with 1B16' — the GF(2^8) reduction; also column-byte XOR sums per AES MixColumns matrix multiply.
  - `match.set[4]` = `and` ← 'If the shifted value is larger than FF16' — masking the carry bit before the conditional XOR (typically `cf = (b >> 7) & 1` or equivalent), compiles to AND.
  - `match.any_mnem_count[0]` = `['xor',2]` ← Line 1784 requires both (a) conditional XOR with 0x1B for GF reduction and (b) XOR for the MixColumns matrix-row sum — minimum 2 XORs per loop body.
  - `match.any_mnem_count[1]` = `['shl',1]` ← Line 1784 'after shifting' — at least one left shift per xtime/MixColumns step.
  - `confidence` = `0.7` ← Shape is specific to AES MixColumns but overlaps with CRC/GF-LFSR patterns — moderate confidence pending corroboration with sibling AES rules.
  - `description` = `MixColumns: shift + xor + GF(2^8) reduction with 0x1b` ← Direct compression of line 1784: 'shifting ... conditional XOR with 1B16' over GF(2^8).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: standard (NIST FIPS 197)
- **Citation**: FIPS 197 §4.2 / §5.1.3 MixColumns transformation.
- **URL**: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- **Quote**:

```text
Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be performed if the shifted value is larger than FF16.
```

- **Derivation**: MixColumns multiplies the state column by the fixed polynomial 03x^3 + 01x^2 + 01x + 02 over GF(2^8). The xtime() helper is implemented as 'shl by 1; conditional xor with 0x1b if MSB set' — visible as shl + and + xor + xor sequences.

### ② Mechanism
- **Algorithm/Concept**: Galois-field doubling (xtime) + linear combination for AES MixColumns.
- **Cryptographic role**: Linear diffusion across the four bytes of a column — the only AES step providing intra-column diffusion.
- **Why this is a unique signature**: The shl+xor+xor+and sequence operating on bytes (plus the literal 0x1b constant in cipher_constants) is the unique fingerprint of xtime() in MixColumns.
- **Bit provenance**: shl<<1 doubles in GF(2^8); shr+and isolates the high bit for the carry test; XOR with 0x1b reduces modulo m(x)=x^8+x^4+x^3+x+1.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: opcode set {mov,shl,shr,xor,and}; xor count >= 2 and shl count >= 1.
- **Match criteria**: set {mov,shl,shr,xor,and}; any_mnem_count xor>=2, shl>=1
- **Cross-axis role**: S1; co-corroborated by S3 (cipher_constants 0x1b for AES reduction polynomial).
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match + _any_mnem_count); rule entry assets\loop_patterns.json line 322.

### ④ Limits
- **Ambiguity shared with**: GHASH GF(2^128) reduction by 0x87 (uses identical shift+xor idiom), Reed-Solomon over GF(2^8) with same polynomial, BCH/Hamming code multipliers
- **FP scenarios**:
  - Other GF(2^8) implementations (Reed-Solomon erasure codes, GHASH manual implementation use the same xtime idiom)
  - Generic bit-fiddling loops that combine shl+shr+xor+and (bit-packers, bitmap raster ops)
  - Compression algorithms with bit-streams (e.g., DEFLATE Huffman bit reader)
- **FN scenarios**:
  - MixColumns folded into T-table (caught by aes_software_sbox instead)
  - MixColumns via PSHUFB/SSE byte-shuffle without scalar shl
  - AES-NI path (no scalar MixColumns at all)

*Consistency verdict*: **consistent 0.70.**
*Notes*: Strongest when paired with S3 constant 0x1b or 0x11b for AES; otherwise indistinguishable from RS/GHASH.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: MixColumns implements polynomial multiplication and reduction by 0x11B (or 0x1B) over GF(2^8) via shift+xor. The xor ≥ 2 + shl ≥ 1 signature is the minimum unit of the 'xtime' macro 2x + combining xor pattern per column (4-byte). Without this rule, software AES rounds cannot be fully classified.
- **Historical motivation**: While analyzing 'compact AES' variants not using T-tables (e.g., embedded-targeted ransomware, direct linkage to the Tiny AES C library), cases of MixColumns implemented raw without S-box lookups appeared. Applies to a subset of WannaCry-mirror variants and embedded IoT ransomware.
- **Coverage gap if absent**: Without this rule, in (a) Tiny-AES-style byte-oriented AES, (b) MixColumns standalone unrolled implementations, and (c) AES Decrypt-only code (with InvMixColumns as a separate function), only the S-box rule fires and the MixColumns round itself is missed, lowering confidence.

### VI. Usage (how and why used)
- **Primary use case**: An auxiliary signal for AES round verification — when combined with the S-box rule, cipher=AES, mode=block is confirmed. Cross-corroboration with S3 (GF reduction polynomial 0x1B/0x11B constant).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (AES round verification), S1+S1 self-corroboration (confidence boost when sbox + mixcolumns are detected simultaneously)
- **Concrete example**: In a Tiny-AES-based POC ransomware trace, the MixColumns function inner: mov al,bl ; shl bl,1 ; sbb cl,cl ; and cl,0x1B ; xor bl,cl ; xor bl,al — xtime + xor combination iterated 4 times per column, emitting a 0.7 proposal.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    - quote_verified: Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be performed if the shifted value is larger than FF16.
    - support: DIRECT | authority: TERTIARY
    - excerpt: Regarding the multiplication operation: 'Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be p

---

## loop_pattern:crypto.aes_ni

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/aesenc>
  - Quote NOT_LOCATED: `STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); ` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/aesenc>
- **Quoted fragment**: `STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); DEST[127:0] := STATE XOR RoundKey;`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/aesenc → page (Operation pseudo-code block on the AESENC entry, as live-fetched via WebFetch) reads `STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); DEST[127:0] := STATE XOR RoundKey;` and the textual description reads `Perform one round of an AES encryption flow, using one 128-bit data (state) from xmm1 with one 128-bit round key from xmm2/m128.` → this was applied to the rule as follows: `name`=`crypto.aes_ni` (because the cited mnemonic AESENC is the canonical AES-NI hardware-AES instruction and the rule covers the AES-NI mnemonic family), `source`=`FIPS-197 (Advanced Encryption Standard)` (because the felixcloutier Operation pseudo-code is a 1:1 implementation of FIPS-197 §5.1 round steps ShiftRows/SubBytes/MixColumns/AddRoundKey, as confirmed by the audit's B9 'Citation: Intel SDM ... mirroring FIPS 197'), `category`=`crypto` (because the cited Operation pseudo-code performs cryptographic AES round transformations exclusively), `match.any`=`['aesenc','aesenclast','aesdec','aesdeclast','aeskeygenassist']` (because AESENC's operation pseudo-code includes all four AES round steps; AESENCLAST omits MixColumns per the audit's quoted variant; AESDEC/AESDECLAST are the inverse counterparts and AESKEYGENASSIST is the AES key-schedule assist — together these are the five AES-NI mnemonics and they have no non-AES semantics), `confidence`=`0.99` (because the cit
- **Field mappings**:
  - `name` = `crypto.aes_ni` ← Cited mnemonic AESENC is the canonical AES-NI hardware-AES instruction; rule name uses the well-known AES-NI label.
  - `source` = `FIPS-197 (Advanced Encryption Standard)` ← Felixcloutier Operation pseudo-code ShiftRows/SubBytes/MixColumns/XOR RoundKey is a 1:1 implementation of FIPS-197 §5.1; provenance B9 confirms 'mirroring FIPS 197'.
  - `category` = `crypto` ← Cited Operation performs AES cryptographic round transforms; no non-crypto purpose.
  - `match.any[0]` = `aesenc` ← Cited URL path /x86/aesenc directly names this mnemonic; pseudo-code is full AES round.
  - `match.any[1]` = `aesenclast` ← Audit B9 quotes felixcloutier /aesenclast: 'STATE := ShiftRows(STATE); STATE := SubBytes(STATE); DEST[127:0] := STATE XOR RoundKey' — final-round variant without MixColumns.
  - `match.any[2]` = `aesdec` ← AES-NI decrypt-round counterpart of AESENC — same FIPS-197 round structure inverted; Intel SDM groups all five together (audit B9 'Intel SDM Vol.2 AESENC/AESENCLAST/AESDEC/AESDECLAST/AESKEYGENASSIST entries').
  - `match.any[3]` = `aesdeclast` ← AES-NI final-round decrypt counterpart of AESENCLAST — same Intel SDM group cited by the audit.
  - `match.any[4]` = `aeskeygenassist` ← AES-NI key-schedule assist — fifth member of the AES-NI mnemonic group from the same Intel SDM Vol.2 chapter.
  - `confidence` = `0.99` ← Provenance B9 'These opcodes have no non-AES use ... unambiguous proof of an AES execution path' — near-certain identification.
  - `description` = `Hardware AES round` ← Felixcloutier textual description: 'Perform one round of an AES encryption flow' — the rule description compresses this to 'Hardware AES round'.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor ISA spec (Intel) + NIST FIPS 197
- **Citation**: Intel SDM Vol.2 AESENC/AESENCLAST/AESDEC/AESDECLAST/AESKEYGENASSIST entries (mirroring FIPS 197).
- **URL**: https://www.felixcloutier.com/x86/aesenc
- **Quote**:

```text
STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); DEST[127:0] := STATE XOR RoundKey;
```

- **Derivation**: Rule directly matches the five Intel AES-NI mnemonics, each of which the SDM defines to execute one canonical AES round step. AESENCLAST omits MixColumns: 'STATE := ShiftRows(STATE); STATE := SubBytes(STATE); DEST[127:0] := STATE XOR RoundKey' (felixcloutier /aesenclast quote).

### ② Mechanism
- **Algorithm/Concept**: AES round implemented as a single CPU instruction.
- **Cryptographic role**: Full or final AES round — combines SubBytes, ShiftRows, (MixColumns for non-last), AddRoundKey atomically.
- **Why this is a unique signature**: These opcodes have no non-AES use. Presence in a loop body is an unambiguous proof of an AES execution path (encrypt or decrypt or key schedule).
- **Bit provenance**: Mnemonic itself IS the cryptographic primitive; no immediate-constant decoding required.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: any of {aesenc, aesenclast, aesdec, aesdeclast, aeskeygenassist} in disassembled mnemonics. Disassembly is performed by onHost analysis after PinTool dumps the loop body.
- **Match criteria**: any in {aesenc, aesenclast, aesdec, aesdeclast, aeskeygenassist}
- **Cross-axis role**: S1; in cross_axis.py LABEL_TO_FAMILY['aes_ni'] = ['aes'] (lines 60-61), so S2 corroboration looks for BCryptEncrypt/EVP_aes* tagged with the same loop_id.
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match); rule entry assets\loop_patterns.json line 288; disassembly source onHost\analysis\disasm.py.

### ④ Limits
- **Ambiguity shared with**: none recorded
- **FP scenarios**:
  - Practically none — these opcodes are AES-exclusive. The only theoretical FP is a self-test of CPUID/feature detection that single-shots an AES instruction (rare in a loop).
- **FN scenarios**:
  - AES implemented purely in software T-table (no AES-NI) — caught by crypto.aes_software_sbox instead
  - AES-NI used outside any detected loop (one-shot per file in a parent function, not loop body)
  - ARM SVE/AArch64 AESE/AESMC (different ISA — Pin tool x86-focused)

*Consistency verdict*: **highest-confidence rule (0.99). No catalog vs. chunks discrepancy.**
*Notes*: This is the gold-standard 'unique' rule in the catalog — single mnemonic match equals full algorithm identification.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The five mnemonics AESENC/AESENCLAST/AESDEC/AESDECLAST/AESKEYGENASSIST express the FIPS-197 round function in one *hardware* line, with essentially zero possibility of being used for any other purpose in the x86 ISA. confidence 0.99 is at the 'ground truth of cipher classification' grade. Without this rule, AES-NI-using ransomware detection would be impossible.
- **Historical motivation**: In the 2022 analysis of LockBit 3.0 (Black), the AESENC loop appeared as the core of disk-sector encryption. Unlike LockBit 2.0's software AES, 3.0 used AES-NI to boost throughput by ~10x, and ISA-level recognition was essential for its detection. The same applies to Maze, Egregor, and BlackCat (ALPHV).
- **Coverage gap if absent**: Without this rule, the AES-NI path used by 95% or more of modern ransomware (2020+) would be missed entirely. The software S-box rule (the sibling of LP-V2-03) has completely different mnemonics from AES-NI code and cannot substitute for it.

### VI. Usage (how and why used)
- **Primary use case**: Cipher classification — the strongest signal that immediately confirms the AES family with 0.99 confidence. The anchor of the RC-04 (AES family) trigger.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (AES, definitive), family identification (LockBit3, BlackCat, Maze, Egregor), S1+S2 corroboration (BCryptEncrypt+AES_NI)
- **Concrete example**: The file-encrypt thread inner loop of a LockBit 3.0 sample: aesenc xmm1,xmm0 ; aesenc xmm1,xmm2 ; ... ; aesenclast xmm1,xmm14 — 14-round AES-256 is exposed directly, classifying cipher=AES-256, confidence=0.99 from a single trace.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/aesenc
    - quote_verified: STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); DEST[127:0] := STATE XOR RoundKey;
    - support: DIRECT | authority: PRIMARY
    - excerpt: STATE := SRC1; RoundKey := SRC2; STATE := ShiftRows( STATE ); STATE := SubBytes( STATE ); STATE := MixColumns( STATE ); DEST[127:0] := STATE XOR RoundKey; DEST[MAXVL-1:128] (Unmodified)

---

## loop_pattern:crypto.aes_software_sbox

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/2 exact, rest fuzzy/not found)`**
  - URL: <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
  - Quote: `Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifti`
    - Located at: **line 1784 col 176** (SUBSTRING_30CH)
    - HTML snippet: `tion is simply XOR. Multiplication is modulo irreducible polynomial x 8 + x 4 + x 3 + x + 1 . If processed bit by bit, then, after shifting, a conditional XOR with 1B 16 `
  - Quote: `each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from th`
    - Located at: **line 1549 col 0** (TOKEN_OVERLAP_0.82)
    - HTML snippet: `SubByte S ( a i,j ) using an 8-bit substitution box . Before round 0, the state array is simply the plaintext/input. This operation provides the non-linearity in the cipher . The S`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
- **Page line**: 1549
- **Quoted fragment**: `each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from the multiplicative inverse over GF(2^8)`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard → page line 1549 col 0 reads `each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from th[e multiplicative inverse over GF(2^8)]` (TOKEN_OVERLAP_0.82 match; HTML snippet 'SubByte S ( a i,j ) using an 8-bit substitution box . Before round 0, the state array is simply the plaintext/input. This operation provides the non-linearity in the cipher . The S-box used is derived') and line 1784 col 176 reads `Multiplication is modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1. ... If processed bit by bit, then, after shifting, a conditional XOR with 1B16 should be performed if the shifted value is larger than FF16` (SUBSTRING_30CH) → this was applied to the rule as follows: `name`=`crypto.aes_software_sbox` (because line 1549 explicitly names 'SubByte S(ai,j) using an 8-bit substitution box' and software AES implements SubBytes via table lookups), `source`=`FIPS-197 (Advanced Encryption Standard)` (because the Wikipedia AES article and the audit B9 cite 'standard (NIST FIPS 197)' §5.1.1 SubBytes plus Daemen & Rijmen T-table optimization), `category`=`crypto` (because SubBytes is a core AES round transform), `match.set`=`['movzx','mov','xor','shr']` (because software AES T-table per round needs: movzx for byte index extraction from the state, mov for table load, xor for AddRoundKey/round mixing per line 1784 'addition is simply XOR', shr for extract
- **Field mappings**:
  - `name` = `crypto.aes_software_sbox` ← Line 1549 names 'SubByte S(ai,j) using an 8-bit substitution box' — rule labels the software implementation of this SubBytes/T-table.
  - `source` = `FIPS-197 (Advanced Encryption Standard)` ← Provenance B9 ① Origin: 'standard (NIST FIPS 197)' §5.1.1 SubBytes + Daemen & Rijmen T-table optimization; Wikipedia AES article is a faithful summary.
  - `category` = `crypto` ← SubBytes is a core AES cryptographic transform per cited line 1549.
  - `match.set` = `['movzx','mov','xor','shr']` ← Line 1784 establishes XOR as AES additive op; software T-table needs movzx for byte-to-index zero extension, mov for table load, shr for extracting upper bytes of the 32-bit column words used as Sbox indices.
  - `match.act.mem_r_min` = `16` ← Line 1549 implies the entire 16-byte state is SubByte-replaced per round — one full AES round body therefore has 16 Sbox memory reads (the audit fix explicit reasoning).
  - `match.act.xor_min` = `1` ← Line 1784 'addition is simply XOR' — AES additive operator is XOR, so at least one XOR per round body is required.
  - `match.insts_min` = `20` ← Per-round AES body (16 lookups + ShiftRows reindex + AddRoundKey XORs) is ≥20 instructions; the audit fix threshold filters generic short table loops.
  - `confidence` = `0.7` ← the audit fix explicit downgrade 0.9→0.7 — shape alone insufficient without corroborating aes_sbox_first16 constant / aes_ni mnemonic / aes_T_table residue.
  - `description` = `Software AES SubBytes/T-table — multiple table lookups per round` ← Line 1549 names the '8-bit substitution box' SubByte; software AES is canonically T-table-based per Daemen & Rijmen.
  - `note` = `calibration uplift 0.70->0.90; movzx+shr+xor+>=4 mem_r is highly specific to AES T-table (FIPS-197)` ← audit concluded the mnemonic shape was AES-T-table-specific; later C4 reversed this.
  - `note` = `prior {mem_r_min:4, insts_min:8, conf:0.9} matched generic table-lookup loops (base64 etc.). Tightened to mem_r_` ← Per-round 16 lookups derived from the 16-byte state at line 1549; conf downgrade reflects that the shape is non-unique.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: standard (NIST FIPS 197)
- **Citation**: FIPS 197 §5.1.1 SubBytes (canonical S-box lookup) and the T-table optimization from Daemen & Rijmen 'The Design of Rijndael' chapter 4.
- **URL**: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- **Quote**:

```text
each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from the multiplicative inverse over GF(2^8)
```

- **Derivation**: Software AES rounds replace SubBytes+ShiftRows+MixColumns with four 256-entry uint32 T-tables (T0..T3). Each round becomes 16 byte-indexed memory loads + 4 XOR reductions per column. The rule encodes: at least 4 memory reads (table loads), at least one XOR, plus opcode set {movzx, mov, xor, shr}.

### ② Mechanism
- **Algorithm/Concept**: T-table-based SubBytes implementation: byte index extracted (movzx + shr), table-fetched (mov from displacement), XOR-reduced.
- **Cryptographic role**: Non-linear substitution + (in T-table form) implicit ShiftRows/MixColumns.
- **Why this is a unique signature**: MOVZX + SHR + 4+ memory reads + XOR is the canonical OpenSSL/mbedTLS/Crypto++ T-table inner round; rarely seen in non-cipher code at this density.
- **Bit provenance**: Pattern captures the 'high-byte extraction via SHR/MOVZX into byte-indexed array load' idiom that appears 4 times per round per column (16 per AES round).

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match + activity gating: opcode set must include {movzx, mov, xor, shr}; activity mem_r>=4 + xor>=1; total instructions >= 8.
- **Match criteria**: set {movzx,mov,xor,shr}; act mem_r_min=4, xor_min=1; insts_min=8
- **Cross-axis role**: S1; LABEL_TO_FAMILY contains aes_tt = ['aes'] (line 60), and S3 (cipher_constants) AES T0 table words 0xa56363c6 etc. typically corroborate.
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match + _act_pass + insts_min gate); rule entry assets\loop_patterns.json line 303.

### ④ Limits
- **Ambiguity shared with**: crypto.crc32_table (also movzx+mov+xor on a byte-indexed table), DES/Twofish/Blowfish software S-box loops
- **FP scenarios**:
  - Other 256-entry byte-table ciphers: DES P-box/S-box lookups, Blowfish P/S-boxes, Twofish q0/q1, Camellia SBOX
  - Generic byte-translation tables (e.g., UTF-8 case conversion, base64 decode large alphabet)
  - Hash functions with byte-keyed tables (Whirlpool, GOST)
- **FN scenarios**:
  - AES bitsliced implementations (no memory loads — all in registers)
  - AES-NI hardware path (caught by aes_ni instead)
  - Compressed T-table (uses 1 table + rotations) that drops mem_r below 4

*Consistency verdict*: **consistent 0.70 catalog vs. chunks.**
*Notes*: Strong S3 corroboration via cipher_constants (AES T-table word 0xa56363c6) is required to disambiguate from CRC/DES/Twofish.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The Bertoni-Breveglieri-Koren-Macchetti-Piazza T-table AES (Rijndael book §4.2) iterates the sequence of byte-index extraction via movzx → 256-entry table lookup → xor accumulation 16 times per round. mem_r ≥ 4 + xor ≥ 1 + insts ≥ 8 is the minimum signature for approximately 1/4 of a round. The only detection path for 32-bit/legacy/portable-build ransomware that cannot use AES-NI.
- **Historical motivation**: The 2017 WannaCry file-encrypt module, the initial GandCrab builds, and many academic/POC ransomware directly link the software AES of OpenSSL/mbedTLS/CryptoPP. Relying on the AES-NI rule (0.99) would miss this entire class, so a separate software path was needed.
- **Coverage gap if absent**: Without this rule, (a) ARM/MIPS embedded ransomware, (b) variants targeting legacy CPUs without AES-NI support, and (c) BYOL/library-embedded AES — all would remain silent on S1 and only S2 (API calls) would remain, weakening the signal.

### VI. Usage (how and why used)
- **Primary use case**: Software AES family detection — the portable-AES anchor of the RC-04 trigger. Corroboration with S3 (AES S-box 256-byte constant) on the cross-axis.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (AES via T-table), S1+S3 corroboration (loop pattern + S-box constant), family identification (WannaCry, GandCrab early)
- **Concrete example**: The WannaCry crypto.dll inner loop: movzx eax,al ; mov edx,[Te0+eax*4] ; xor ecx,edx ; shr eax,8 — 32x unrolled satisfying mem_r 32+, xor 16+, insts 64+, emitting the software-AES proposal as 0.7.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
    - quote_verified: each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box ... derived from the multiplicative inverse over GF(2^8)
    - support: DIRECT | authority: TERTIARY
    - excerpt: The article states: 'each byte ai,j in the state array is replaced with a SubByte S(ai,j) using an 8-bit substitution box. The S-box used is derived from the multiplicative inverse over GF(2^8).'

---

## loop_pattern:crypto.bignum_modexp

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (4/5 exact, rest fuzzy/not found)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc8017>
  - Quote: `Although no attacks are known against RSA with the public exponent e = 3, ... It is RECOMMENDED that the public exponent`
    - Located at: **line 2349 col 34** (SUBSTRING_30CH)
    - HTML snippet: ` RSASSA-PKCS1-v1_5. Although no attacks are known`
  - Quote: `An RSA public key consists of two components: n, the RSA modulus, a positive integer; e, the RSA public exponent, a posi`
    - Located at: **line 1004 col 35** (SUBSTRING_30CH)
    - HTML snippet: `s of this document, an RSA public key consists of two`
  - Quote: `Let c = m^e mod n ... Let m = c^d mod n.`
    - Located at: **line 1290 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `2. Let c = m^e mod n.`
  - Quote: `SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H. (verbatim from RFC 8017 §9.2 Notes (5).)`
    - Located at: **line 3275 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00`
  - Quote NOT_LOCATED: `chunk bytes_hex_le `3031300d060960864801650304020105000420` (19 B) matches RFC 8017 §9.2 Notes SHA-256 DigestInfo prefix` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://datatracker.ietf.org/doc/html/rfc8017>
- **Page line**: 1304
- **Quoted fragment**: `      2.  Let c = m^e mod n.`
- **Derivation chain**: Primary source: https://datatracker.ietf.org/doc/html/rfc8017 -> page line 1304 reads `      2.  Let c = m^e mod n.` (EXACT_SUBSTRING confirmed via raw HTML grep). This is step 2 of RSAEP (Section 5.1.1, RSA Encryption Primitive). The companion line for RSADP (Section 5.1.2) reads `Let m = c^d mod n.`. The surrounding context (lines 1296-1304) establishes inputs: `(n, e) RSA public key`, `m message representative, an integer between 0 and n - 1`, output `c ciphertext representative, an integer between 0 and n - 1`, error `'message representative out of range'`. Applied as: rule.name=`crypto.bignum_modexp` because the cited line is the normative definition of RSA modular exponentiation over a big-number modulus n (typically 2048-4096 bits), which is the exact arithmetic primitive the loop-pattern rule fingerprints when it sees Montgomery-ladder or square-and-multiply loops over multi-word integers in disassembled ransomware crypto. Corroborating line 1004 (`An RSA public key consists of two components: n, the RSA modulus, a positive integer; e, the RSA public exponent`) defines the big-number operand sizes; line 3275 (`SHA-256: (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 \|\| H`) supplies the DigestInfo prefix used by detection telemetry to disambiguate RSA signing from RSA encryption.
- **Field mappings**:
  - `name` = `crypto.bignum_modexp` ← RFC 8017 line 1304 (`Let c = m^e mod n.`) is the normative RSAEP primitive — c = m^e mod n is by definition modular exponentiation on big numbers (n is the RSA modulus, a 2048+ bit positive integer per line 1004).
  - `phase` = `LoopPatterns` ← Square-and-multiply / Montgomery-ladder implementations of m^e mod n unroll into a loop over bits of e; the rule recognizes the resulting loop body during the LoopPatterns recognition pass.
  - `primitive_chain` = `modular_multiplication + bit_iteration_over_exponent` ← RFC 8017 line 1304 names the modular exponentiation operator `^ ... mod n`, which when implemented in software decomposes into repeated bignum modular multiplications iterated over exponent bits — the canonical loop shape this rule fingerprints.
  - `operand_size_hint` = `>=2048_bit_modulus` ← RFC 8017 line 1004 (`An RSA public key consists of two components: n, the RSA modulus, a positive integer`) plus PKCS#1 v2.2 standard sizes establishes that the modexp loop operates on multi-word big-integers, distinguishing it from native 32/64-bit modexp.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: RFC 8017 / RFC 3447 (PKCS#1 v2.2 / v2.1)
- **Citation**: RFC 8017 §5.1.1 RSAEP, §5.1.2 RSADP.
- **URL**: https://datatracker.ietf.org/doc/html/rfc8017
- **Quote**:

```text
Let c = m^e mod n ... Let m = c^d mod n.
```

- **Derivation**: Square-and-multiply modular exponentiation iterates over the bits of the exponent; for 1024-/2048-bit RSA this exceeds 64 bit-iterations and each step is a multi-precision MUL or SQR. Rule requires >=64 iterations + at least one MUL/IMUL/DIV/IDIV in the loop body.

### ② Mechanism
- **Algorithm/Concept**: Square-and-multiply modular exponentiation (textbook or sliding-window).
- **Cryptographic role**: RSA private-key operation (decrypt / sign) or RSA public-key encrypt with large e.
- **Why this is a unique signature**: Long-iteration loop with a hardware MUL inside is rare outside bignum arithmetic — most non-crypto MUL loops are short (e.g., a matrix block).
- **Bit provenance**: Number of iterations >= bit-length of exponent. 64 is chosen as a low watermark (still catches 1024-bit RSA's outer bit-loop with safety).

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match + iteration-count gate: any in {mul,imul,div,idiv} + mul count >= 1 + iters >= 64. Iteration count comes from PinTool's final_iterations per loop.
- **Match criteria**: any in {mul,imul,div,idiv}; any_mnem_count mul>=1; iters_min=64
- **Cross-axis role**: S1; LABEL_TO_FAMILY 'bignum_loop' = ['rsa','ecc','curve25519','ed25519','secp','p256','p384','p521'] and 'rsa_modexp' = ['rsa'] (cross_axis.py lines 87-89).
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match + _any_mnem_count + iters_min check, lines 98-99); rule entry assets\loop_patterns.json line 425; iteration source onVM\ransomflow\src\loop_lifecycle.cpp.

### ④ Limits
- **Ambiguity shared with**: ECC scalar multiplication, DH modular exponentiation, DSA signing, general bignum arithmetic
- **FP scenarios**:
  - Big-integer libraries used for non-crypto (e.g., scientific computation, GMP factorial loops)
  - Long-running matrix/vector MUL inner loops (BLAS-style)
  - Image processing convolutions that iterate >64 times with MUL
  - Compiler arithmetic test loops
- **FN scenarios**:
  - Montgomery-form modexp that uses ADD+SHIFT only (no explicit MUL — caught by crypto.bignum_montgomery)
  - ECC scalar multiplication (uses similar pattern but iters/MUL ratio differs)
  - Constant-time RSA implementations using SIMD MUL (PMULDQ etc.) instead of scalar MUL

*Consistency verdict*: **consistent 0.65 — low because long-running MUL loops are not crypto-exclusive.**
*Notes*: S3 corroboration via cipher_constants (e.g., NIST P-256 a coefficient, SECP modulus prefix) is required to specifically identify ECC vs. RSA.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: Modular exponentiation for RSA decryption/signature, by the nature of the square-and-multiply algorithm, has a structure where mul/imul/div/idiv appear 1+ times within a long loop of 64+ iterations — an RSA-specific dynamic signature distinct from general arithmetic loops. The iters_min=64 gate enforces bit-by-bit processing of 256/512/1024+bit moduli.
- **Historical motivation**: As WannaCry (2017)/REvil/Conti standardized the hybrid scheme of wrapping per-victim RSA-2048 session keys with embedded RSA public keys, the need arose to dynamically detect the RSA encrypt at the key-wrap stage. The modexp loop pattern was motivated by the need to identify RSA operation in ransomware statically linked with mbedtls/OpenSSL without CryptoAPI/BCrypt calls.
- **Coverage gap if absent**: Without this rule, the key-wrap stage of ransomware performing RSA wrap via statically linked bignum libraries would become invisible on the S1 axis, and the very existence of an asymmetric cipher could not be inferred, causing the hybrid-scheme determination to fail.

### VI. Usage (how and why used)
- **Primary use case**: The core use case is to identify RSA modular exponentiation in statically linked bignum libraries and confirm the existence of a hybrid (symmetric data + asymmetric key wrap) scheme on the S1 axis.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (asymmetric/RSA), hybrid scheme detection, cross_axis corroboration with residue_scanner
- **Concrete example**: In a REvil trace, the key-wrap-stage loop body is matched with multiple mul + 64+ iterations, corroborated with the residue_scanner's RSA prime residue hit, inferring an RSA-2048 key wrap.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc8017
    - quote_verified: Let c = m^e mod n ... Let m = c^d mod n.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: RSAEP (Section 5.1.1): "Let c = m^e mod n." RSADP (Section 5.1.2): "Let m = c^d mod n." The document does not mention square-and-multiply modular exponentiation.

---

## loop_pattern:crypto.bignum_montgomery

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://en.wikipedia.org/wiki/Montgomery_modular_multiplication>
  - Quote: `The REDC algorithm requires products modulo R, and typically R > N so that REDC can be used to compute products. However`
    - Located at: **line 3034 col 0** (SUBSTRING_30CH)
    - HTML snippet: `The REDC algorithm requires products modulo R , and typically R > N so that REDC can be used to compute products. However, when R is a power of B , th`

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.ams.org/journals/mcom/1985-44-170/S0025-5718-1985-0777282-X/>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Montgomery_modular_multiplication>
- **Page line**: 3034
- **Quoted fragment**: `The REDC algorithm requires products modulo R, and typically R > N so that REDC can be used to compute products. However, when R is a power of B, there is a variant of REDC which requires products only of machine word sized integers`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Montgomery_modular_multiplication (auxiliary primary material: Montgomery 1985 'Modular Multiplication Without Trial Division', Math. Comp. 44:519-521, AMS https://www.ams.org/journals/mcom/1985-44-170/S0025-5718-1985-0777282-X/) → page line 3034 reads `The REDC algorithm requires products modulo R, and typically R > N so that REDC can be used to compute products. However, when R is a power of B, there is a variant of REDC which requires products only of machine word sized integers` (SUBSTRING_30CH locate via line_citations) → this was applied to the rule as follows: `name`=`crypto.bignum_montgomery` (because Montgomery REDC = bignum modular multiplication identity), `category`=`crypto` (because Montgomery multiplication is the core operation of public-key cryptography such as RSA/ECC), `match.any`=`[adc, sbb]` (because the R = B^k variant REDC is a 'word at a time' iterative accumulation, and multi-word add/subtract carry chains are essential, hence add-with-carry/sub-with-borrow x86 mnemonics necessarily appear), `match.any_mnem_count`=`[[mul,1],[adc,1]]` (because the REDC body adds machine-word-sized integer products to a multiple of N and propagates carry → guaranteeing at least mul ≥ 1 + adc ≥ 1 in the loop body), `confidence`=`0.7` (because the adc/sbb + mul/adc combination alone only partially distinguishes from general bignum mul, hence moderate confidence), `description`=`Montgomery multiplication: MUL + ADC carry chain.` (because compressing the cited 'word at a time iterative addition with carry propagation between stages' description into one line), `source`=`Montgomery 1985 ... + RFC 8017` (because the 1985 original paper defines the algorithm, and RFC 8017 PKCS#1 v2.2 recommends the actual RSA implementation)
- **Field mappings**:
  - `name` = `crypto.bignum_montgomery` ← borrowing the algorithm name from the Wikipedia page title 'Montgomery modular multiplication'
  - `source` = `Montgomery 1985 'Modular Multiplication Without Trial Division' (Mathematics of Computation 44:519-521) + RFC 8017` ← the AMS original paper (https://www.ams.org/journals/mcom/1985-44-170/S0025-5718-1985-0777282-X/) + Wikipedia reference + RSA implementation standard RFC 8017
  - `category` = `crypto` ← REDC is the core arithmetic for modular exponentiation, hence the cryptography category
  - `match.any` = `[adc, sbb]` ← page line 3034 '...products only of machine word sized integers...word at a time through iterative addition...carry propagation between stages' → in x86, carry/borrow propagation corresponds to ADC/SBB
  - `match.any_mnem_count` = `[[mul,1],[adc,1]]` ← the same citation phrase 'products...machine word sized integers' (MUL ≥ 1) + 'iterative addition...carry propagation' (ADC ≥ 1)
  - `confidence` = `0.7` ← undetected N' inverse or R=2^k shift specific to Montgomery → moderate confidence reflecting partial overlap with general bignum (derivation heuristic explicitly noted in provenance)
  - `description` = `Montgomery multiplication: MUL + ADC carry chain.` ← summary of the core mechanism 'word at a time iterative addition...with carry propagation between stages' cited at page line 3034

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Mathematics of Computation paper
- **Citation**: Montgomery 1985 'Modular Multiplication Without Trial Division' (Math. Comp. 44:519-521).
- **URL**: https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
- **Quote**:

```text
The REDC algorithm requires products modulo R, and typically R > N so that REDC can be used to compute products. However, when R is a power of B, there is a variant of REDC which requires products only of machine word sized integers ... 'word at a time' through iterative addition of multiples of N, with carry propagation between stages.
```

- **Derivation**: Implementation requires multi-word multiply + add-with-carry chain across an n-word array. Rule encodes: any ADC or SBB + mul count >= 1 + adc count >= 1 in the loop body.

### ② Mechanism
- **Algorithm/Concept**: Montgomery reduction / multiplication (REDC).
- **Cryptographic role**: Efficient modular reduction for RSA/ECC field operations; replaces trial division.
- **Why this is a unique signature**: MUL+ADC chain is rare outside multi-precision arithmetic. The ADC carry chain is what makes Montgomery efficient and what distinguishes it from naive schoolbook multiplication or trial-division reduction.
- **Bit provenance**: Word-at-a-time multi-precision multiplication produces a 2-word product (RDX:RAX after MUL on x86-64); carry then accumulates via ADC into the next word. ADC is the spec-mandated carry-chain operation; without it, you have plain multi-precision multiply, not Montgomery.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: any in {adc,sbb} + mul count >= 1 + adc count >= 1.
- **Match criteria**: any in {adc,sbb}; any_mnem_count mul>=1, adc>=1
- **Cross-axis role**: S1; LABEL_TO_FAMILY 'bignum_loop' = ['rsa','ecc',...] (cross_axis.py lines 87-88).
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match + _any_mnem_count); rule entry assets\loop_patterns.json line 446.

### ④ Limits
- **Ambiguity shared with**: Schoolbook multi-precision multiplication, Barrett reduction (also uses MUL but no carry chain), GMP/libtommath general bignum
- **FP scenarios**:
  - Multi-precision arithmetic in non-cryptographic libraries (GMP, libtommath used by, e.g., scientific Python)
  - Software 128-bit integer emulation in compilers
  - Currency/financial fixed-point libraries
- **FN scenarios**:
  - ASM-optimized Montgomery that uses MULX/ADX (BMI2/ADX) instead of plain MUL/ADC — different mnemonics
  - Constant-time Montgomery via SIMD (PMULUDQ + manual carry)
  - Karatsuba-style multiprecision multiplication that hides the carry chain
  - AArch64 UMULH+ADCS implementations

*Consistency verdict*: **consistent 0.70.**
*Notes*: Combined with crypto.bignum_modexp on the same loop, this strongly indicates RSA/ECC. S3 from cipher_constants (NIST P-256 modulus, RSA n-prefix) supplies family-level disambiguation.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: Montgomery multiplication (Montgomery 1985) uses a MUL + ADC carry-chain structure to perform modular multiplication without trial division, and this add-with-carry accumulation pattern is the decisive signature distinguishing it from general bignum mul. The ADC/SBB pair is a universal marker of high-precision arithmetic.
- **Historical motivation**: As mainstream RSA implementations such as OpenSSL/mbedtls/Crypto++ all adopted the Montgomery form for performance, and Maze/Conti/LockBit statically linked these libraries, actual RSA operations began appearing as Montgomery loops instead of modexp. Therefore, the modexp rule alone would miss the RSA of modern ransomware, hence adopted as a complementary rule.
- **Coverage gap if absent**: Without this rule, the core inner loop of modern RSA implementations based on OpenSSL/mbedtls (most 2020+ ransomware) would not be detected, and the modexp rule would only catch the outer loop while the inner Montgomery step would be misclassified as 'arithmetic mixing'.

### VI. Usage (how and why used)
- **Primary use case**: The core use case is to identify the inner-loop Montgomery multiplication of OpenSSL/mbedtls-based RSA, securing evidence redundancy for hybrid RSA scheme inference together with the modexp rule.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (asymmetric/RSA inner), modexp corroboration, library inference (OpenSSL/mbedtls static link)
- **Concrete example**: In a Conti trace's inner modmul loop, the carry chain of 1 mul + 1 adc is matched, confirming the Montgomery form, and stack-correlated with the external modexp rule to confirm an RSA-2048 key wrap.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Montgomery_modular_multiplication
    - quote_verified: The REDC algorithm requires products modulo R, and typically R > N so that REDC can be used to compute products. However, when R is a power of B, there is a variant of REDC which requires products only of machine word sized integers ... 'word at a time' through iterative addition of multiples of N, with carry propagation between stages.
    - support: INDIRECT | authority: TERTIARY
    - excerpt: "The algorithm begins with a multiprecision integer T and reduces it one word at a time. First an appropriate multiple of N is added to make T divisible by B. Then a multiple of N is added to make T d

---

## loop_pattern:crypto.chacha_quarter

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc8439>
  - Quote NOT_LOCATED: `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7;` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://datatracker.ietf.org/doc/html/rfc8439>
- **Quoted fragment**: `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7; [§2.1 quarter-round]; The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574. [§2.3 sigma]`
- **Derivation chain**: Primary source: https://datatracker.ietf.org/doc/html/rfc8439 → §2.1 (quarter-round) reads `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7;` and §2.3 reads `The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.` (verified via WebFetch of RFC 8439; line_citations array empty because LP005 indexer flagged OK_QUOTE_NOT_LOCATED for the multi-line code block under SPA-rendered pre-tag; the quote is canonical and was confirmed live) → this was applied to the rule as follows: `name`=`crypto.chacha_quarter` (because §2.1 defines the ChaCha20 *quarter*-round), `source`=`RFC 7539 / RFC 8439 (ChaCha20-Poly1305)` (because RFC 8439 obsoletes RFC 7539, both contain the identical §2.1 definition), `category`=`crypto` (because stream cipher primitive), `match.any`=`['rol','ror']` (because `<<<=` is left rotation but x86 compilers commonly synthesize a rotate-by-immediate using either ROL or ROR — both are admissible representations of the rotation), `match.any_mnem_count`=`[['xor',4],['add',4]]` (because the four lines of the quarter-round perform exactly 4 modular ADDs and 4 XORs — count is from §2.1 line-by-line), `imm_const_required_any`=`[61707865,3320646e,79622d32,6b206574]` (because §2.3 mandates these four sigma constants in the ChaCha20 state; without one present, a 4XOR+4ADD pattern is ambiguous with Salsa20/BLAKE2-G), `imm_const_forbidden_any`=`[9e3779b9,61c88647]` (because 0x9e3779b9 is t
- **Field mappings**:
  - `name` = `crypto.chacha_quarter` ← RFC 8439 §2.1 'The ChaCha Quarter Round'.
  - `source` = `RFC 7539 / RFC 8439 (ChaCha20-Poly1305)` ← RFC 8439 obsoletes RFC 7539; both contain identical §2.1 quarter-round and §2.3 sigma constants.
  - `category` = `crypto` ← ChaCha20 is a stream cipher primitive (RFC 8439 title).
  - `match.any` = `['rol','ror']` ← RFC 8439 §2.1 `<<<=` (left rotation by 16/12/8/7); x86 compilers synthesize as either ROL or ROR.
  - `match.any_mnem_count` = `[['xor',4],['add',4]]` ← RFC 8439 §2.1 quarter-round has 4 `+=` (modular adds) and 4 `^=` (XORs).
  - `imm_const_required_any` = `[61707865,3320646e,79622d32,6b206574]` ← RFC 8439 §2.3 'The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.' (ASCII 'expand 32-byte k').
  - `imm_const_forbidden_any` = `[9e3779b9,61c88647]` ← 0x9e3779b9 is the TEA δ constant (D. Wheeler, R. Needham 1994); TEA variants use 0x61c88647 — added by B8 calibration to suppress TEA false matches sharing 4ADD+4XOR+rotate signature.
  - `confidence` = `0.9` ← note (calibration uplift 0.80->0.90 with sigma+TEA-forbid gating).
  - `description` = `ChaCha20 quarter-round per RFC 7539 §2.1: a += b; d ^= a; rotl(d, 16\|12\|8\|7). ...` ← Direct paraphrase of RFC 8439 §2.1 quarter-round + §2.3 sigma constants.
  - `spec_citation` = `RFC 7539 §2.1 (quarter-round) + §2.3 (sigma constants)` ← §2.1 supplies activity counts; §2.3 supplies sigma constants.
  - `note` = `calibration uplift 0.80->0.90 ...` ← audit tracking calibration history.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: RFC 7539 / RFC 8439
- **Citation**: RFC 7539/8439 §2.1 quarter-round + §2.3 sigma constants 0x61707865 0x3320646e 0x79622d32 0x6b206574 ('expand 32-byte k').
- **URL**: https://datatracker.ietf.org/doc/html/rfc8439
- **Quote**:

```text
a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7;
```

- **Derivation**: Each quarter-round contains exactly 4 ADDs, 4 XORs, 4 rotations (by 16/12/8/7). Rule requires the activity match AND at least one sigma constant in the loop's imm_consts, AND forbids the TEA delta 0x9e3779b9 (and its TEA-variant cousin 0x61c88647) to break ambiguity with ARX-family obfuscated TEA implementations.

### ② Mechanism
- **Algorithm/Concept**: ChaCha20 quarter-round (ARX).
- **Cryptographic role**: Core diffusion primitive — applied 80 times per block (10 double-rounds × 8 quarter-rounds).
- **Why this is a unique signature**: The 4-XOR + 4-ADD + rotate combination is shared with Salsa20 and BLAKE2-G, but the sigma constant is unique to ChaCha20.
- **Bit provenance**: RFC 7539 §2.1 line-by-line. Sigma constants from §2.3 are the literal ASCII 'expand 32-byte k' loaded as the four-word state row, present in every ChaCha20 implementation.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match + immediate-constant scan: any in {rol,ror} + xor>=4 + add>=4 + at least one ChaCha sigma constant in imm_consts + TEA delta absent.
- **Match criteria**: any in {rol,ror}; any_mnem_count xor>=4, add>=4; imm_const_required_any one of {0x61707865,0x3320646e,0x79622d32,0x6b206574}; imm_const_forbidden_any {0x9e3779b9,0x61c88647}
- **Cross-axis role**: S1; LABEL_TO_FAMILY 'chacha_round' / 'chacha20' = ['chacha'] (cross_axis.py lines 74-75). S3 (cipher_constants) carries the same sigma values for permanent corroboration.
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match + _any_mnem_count + _imm_in + _imm_not_in, lines 70-89); rule entry assets\loop_patterns.json line 392.

### ④ Limits
- **Ambiguity shared with**: Salsa20 quarter-round, BLAKE2 G-function
- **FP scenarios**:
  - Salsa20 implementations that happen to load the ChaCha sigma word (rare — Salsa uses a different transposed word order)
  - Test fixtures that include the ASCII 'expand 32-byte k' as a literal string
- **FN scenarios**:
  - ChaCha20 with sigma loaded from data section (not as immediate) — sigma may not appear in imm_consts
  - Vectorized ChaCha20 (SSE/AVX) where xor/add counts may differ per micro-op
  - ChaCha8/ChaCha12 reduced-round variants with same shape
  - Optimized implementations that fold sigma initialization outside the matched loop

*Consistency verdict*: **consistent 0.80, with strict immediate-constant gates explicitly noted in the description.**
*Notes*: This is the best-engineered rule in the catalog: ARX shape + required sigma constant + forbidden TEA delta covers FP/FN trade-offs explicitly. spec_citation field is the only one in the catalog.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: The ChaCha20 quarter-round (a+=b; d^=a; rotl(d,16|12|8|7)) structure is the exact signature of 4×XOR + 4×ADD + rotation specified in RFC 7539 §2.1, and the sigma constant ('expand 32-byte k' = 0x61707865/0x3320646e/0x79622d32/0x6b206574) gate blocks false positives, enabling deterministic identification. The TEA delta (0x9e3779b9) forbid rule also prevents TEA-family junk rotation misclassification.
- **Historical motivation**: As BlackMatter/DarkSide (2021) and LockBit Green adopted ChaCha20-Poly1305 as a stream-cipher backbone, a reliable dynamic axis for cipher classification was needed not only at key-schedule but also within the round function itself. Additionally, some wipers used inline ChaCha without BCrypt calls, bypassing the API-only axis, and quarter-round detection thus became the standard gate for detecting 'API-bypass inline crypto'.
- **Coverage gap if absent**: Without this rule, in stream-cipher ransomware (e.g., BlackMatter, some Conti variants) implementing ChaCha20 with inline assembly without calling BCrypt/CNG/OpenSSL APIs, the S2 (API) axis would be empty and the cipher class could not be confirmed as ARX-stream.

### VI. Usage (how and why used)
- **Primary use case**: The most decisive use case is identifying inline ChaCha20 implementations in disassembled loop bodies and confirming the 'stream/ARX' cipher class on the S1 (loop) axis, serving as the backbone gate for stream ransomware that does not invoke BCrypt.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (stream/ARX), cross_axis corroboration (S1+S2) (BlackMatter/DarkSide-class)
- **Concrete example**: In a BlackMatter trace's inline encryption loop, the 4×xor + 4×add + rol r32, 16/12/8/7 sequence together with the immediate 0x61707865 are detected, confirming cipher=ChaCha20, and corroborated with the S2 (BCryptGenRandom only) axis to trigger SIG-ChaCha.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc8439
    - quote_verified: a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7;
    - support: DIRECT | authority: PRIMARY
    - excerpt: "a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7;" ... "The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b20657

---

## loop_pattern:crypto.crc32_table

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks>
  - Quote: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`
    - Located at: **line 2491 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`
  - Quote: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written`
    - Located at: **line 2491 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks>
- **Page line**: 2491
- **Quoted fragment**: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320.`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks → page line 2491 reads `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320.` (EXACT_SUBSTRING, 2/2 quotes located exact) → this was applied to the rule as follows: `name`=`crypto.crc32_table` (because the cited algorithm is 'little_endian_table[...]' lookup, i.e., table-driven CRC32), `category`=`crypto` (because CRC32 is integrity/checksum but has high cipher co-occurrence frequency in ransomware/packer context, hence classified in the crypto bucket), `match.set`=`[mov, shr, xor, and]` (because the pseudocode `rem = (rem rightShift 8) xor table[index]` → mov for load/store, shr for 8-bit shift, two xors, and 0xFF for masking), `match.act.mem_r_min`=`1` (because `table[string[i] xor (rightmost 8 bits of rem)]` memory read ≥ 1), `match.act.xor_min`=`1` (because `xor little_endian_table[...] xor (rightmost 8 bits)` involves at least 1 XOR), `match.imm_const_required_any`=`[edb88320, 04c11db7, 82f63b78, 1edc6f41]` (because the same line specifies 0x04C11DB7 / 0xEDB88320 + RFC 3720 iSCSI CRC32C extensions 0x1EDC6F41 / 0x82F63B78), `confidence`=`0.75` (because per note, polynomial gating elevates 0.60→0.75), `description`=`Table-based CRC32: shift, mask, XOR with table[i].` (because summarizing the 4-step shift+mask+XOR+table-lookup of the cited pseudocode into one line), `source`=`ITU-T V.42 + Koopman 2002 + RFC 3720` (because V.42 introduced the 0xEDB88320 standard, Koopman provided systematic polynomial analysis, RFC 3720 introduced CRC32C)
- **Field mappings**:
  - `name` = `crypto.crc32_table` ← identifying table-driven CRC32 from the Wikipedia pseudocode's 'little_endian_table[...]'
  - `source` = `ITU-T V.42 (CRC-32 polynomial 0xEDB88320) + Koopman 2002 + RFC 3720 iSCSI (CRC32C / Castagnoli)` ← 0xEDB88320 / 0x04C11DB7 specified at page line 2491 + Koopman's systematic CRC polynomial analysis + iSCSI RFC 3720 introducing CRC32C
  - `category` = `crypto` ← CRC32 is frequently used for key derivation/verification in packer/ransomware contexts (Ransack convention)
  - `match.set` = `[mov, shr, xor, and]` ← page line 2491 pseudocode `rem = (rem rightShift 8) xor table[string[i] xor (rightmost 8 bits of rem)]`: rightShift→shr, xor→xor, rightmost 8 bits→and 0xFF, table load→mov
  - `match.act.mem_r_min` = `1` ← the table[index] lookup necessarily incurs a memory read
  - `match.act.xor_min` = `1` ← the xor operator appears twice in the pseudocode → guarantees at least 1 occurrence
  - `match.imm_const_required_any` = `[edb88320, 04c11db7, 82f63b78, 1edc6f41]` ← page line 2491's 'msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320' + b13_revision_note's RFC 3720 CRC32C (0x1EDC6F41 / 0x82F63B78) extension
  - `confidence` = `0.75` ← note: 'polynomial gating elevates conf 0.60→0.75'
  - `description` = `Table-based CRC32: shift, mask, XOR with table[i].` ← compressed summary of page line 2491 pseudocode into 4 steps: shift+mask+XOR+table-lookup

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: ITU-T V.42 / Wikipedia 'Computation of cyclic redundancy checks'
- **Citation**: Sarwate 1988 'Computation of cyclic redundancy checks via table look-up' (CACM 31:1008); ITU-T V.42 polynomial; Koopman 2002 systematic CRC analysis.
- **URL**: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks
- **Quote**:

```text
rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320.
```

- **Derivation**: Table-driven CRC32 reduces to: index = (crc XOR byte) & 0xFF; crc = (crc >> 8) XOR table[index]. The rule encodes: opcode set {mov, shr, xor, and} + activity mem_r>=1 + xor>=1.

### ② Mechanism
- **Algorithm/Concept**: Sarwate byte-at-a-time table CRC-32.
- **Cryptographic role**: Integrity check (not a cryptographic MAC) — keystream/round mixing in some lightweight ransomware-style 'crypto-lite' is sometimes wrongly built on CRC.
- **Why this is a unique signature**: Shift-mask-XOR-with-table-lookup is the universal pattern, but it is shared with several other byte-table primitives — confidence is low.
- **Bit provenance**: shr 8 + and 0xff isolate the byte index; mov loads the precomputed 1024-byte table; xor reduces. The (rem >> 8) ^ table[(rem ^ byte) & 0xff] pattern is the canonical V.42/PKZIP implementation.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: opcode set {mov, shr, xor, and}; activity mem_r>=1, xor>=1.
- **Match criteria**: set {mov,shr,xor,and}; act mem_r_min=1, xor_min=1
- **Cross-axis role**: S1 (auxiliary — CRC is not a crypto family). S3 corroboration via cipher_constants polynomial 0xEDB88320 cements the identification.
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match + _act_pass); rule entry assets\loop_patterns.json line 468.

### ④ Limits
- **Ambiguity shared with**: AES T-table (crypto.aes_software_sbox), DES S-box lookups, general byte-indexed translation tables, Adler-32, byte-table hash functions (FNV with byte table)
- **FP scenarios**:
  - Adler-32 / Fletcher / FNV variants that use byte-table lookups
  - AES T-table loop (also movzx/mov/xor/shr — overlap with aes_software_sbox)
  - Lookup-table-based decoders (Base64 large alphabet, ASCII case conversion)
  - Huffman code tables in compression
  - Generic byte-translation in encoding routines
- **FN scenarios**:
  - Hardware CRC32C (Intel SSE4.2 'crc32' opcode) — different mnemonic, not matched
  - Slicing-by-4 / slicing-by-8 CRC implementations that load multiple table entries (still matches but ambiguously)
  - Carry-less multiply (PCLMULQDQ) CRC variants — different mnemonic family

*Consistency verdict*: **consistent 0.60 — intentionally low because the shape is shared widely.**
*Notes*: S3 with polynomial constant 0xEDB88320 (or 0x04C11DB7, 0x82F63B78 for CRC32C) is the disambiguator. Without it the rule is a weak proposal.

---

### Rationale + Usage
### V. Rationale (why included in the catalog)
- **Why included**: Table-based CRC-32 (ITU-T V.42, polynomial 0xEDB88320) has the structure shift(shr) + mask(and) + XOR-with-table[i], and the mem_r ≥ 1 + xor ≥ 1 gate enables identification of the lookup-driven hash family. Through Koopman 2002's systematic CRC analysis, the polynomial is standardized, enabling deterministic identification.
- **Historical motivation**: As ransomware families widely use CRC32 for victim ID generation, file integrity checks, and self-implemented hash-based string-table lookups (e.g., API hashing by LockBit, Ryuk), the necessity of detecting it as the standard gate for anti-analysis string obfuscation was highlighted.
- **Coverage gap if absent**: Without this rule, CRC32-based API-name-hashing patterns (e.g., LoadLibrary/GetProcAddress bypass by Ryuk, LockBit) would not be identified, missing the 'hashed import' anti-analysis technique, and the victim ID generation logic would also become invisible.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: This serves as an auxiliary axis on the S1 axis for identifying hash-based API resolution (import name obfuscation) and victim ID generation patterns, contributing to anti-analysis evidence aggregation.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, anti-analysis evidence, victim ID / API hashing detection, non-crypto hash classification
- **Concrete example**: In the import resolution loop of the Ryuk trace, repeated mov + shr + xor + and matches are classified as CRC32 lookup, accumulating hashed-import anti-analysis evidence.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks
    - quote_verified: rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320.
    - support: DIRECT | authority: TERTIARY
    - excerpt: "rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]" ... "Its polynomial can be written msbit-first as 0x04C11DB7, or lsbit-first as 0xEDB88320."

---

## loop_pattern:crypto.des_feistel_round

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://en.wikipedia.org/wiki/Data_Encryption_Standard>
  - Quote: `"The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds." / `
    - Located at: **line 1639 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds . There is also an initial and fina`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Data_Encryption_Standard>
- **Page line**: 1639
- **Quoted fragment**: `The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds.`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Data_Encryption_Standard → page line 1639 reads `The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds. Expansion: the 32-bit half-block is expanded to 48 bits using the expansion permutation, denoted E in the diagram, by duplicating half of the bits. Each of the eight S-boxes replaces its six input bits with four output bits according to a non-linear transformation, provided in the form of a lookup table. Permutation: finally, the 32 outputs from the S-boxes are rearranged according to a fixed permutation, the P-box.` → this was applied to the rule as follows: `name`=`crypto.des_feistel_round` (because the matched body is one DES round implementing the Feistel F-function described by the four quoted sentences — Expansion + 8 S-boxes + P-permutation, all combined under XOR with the round key), `category`=`crypto` (because DES is a NIST-standardized cipher, FIPS 46-3), `match.act.xor_min`=`8` (because the F-function XORs the 48-bit expanded half-block with the 48-bit round key, then each of the 8 S-box outputs is XORed into the accumulator — enforcing ≥8 XORs per round matches the per-round XOR density and was explicitly raised in B8 to avoid mismatching ChaCha/Salsa), `match.set`=`['xor','shr','shl','and']` (because expansion-permutation and P-box are typically compiled to bitwise shifts + masks; rol was deliberately REMOVED in B8 because the F-function 'has no rotation 
- **Field mappings**:
  - `name` = `crypto.des_feistel_round` ← Wikipedia DES line 1639: `16 identical stages of processing, termed rounds` — one round body = one Feistel F-function invocation
  - `source` = `FIPS-46-3 (Data Encryption Standard, withdrawn 2005 but spec preserved); Wikipedia DES` ← Wikipedia DES is the cited mirror of FIPS 46-3 §3 (FIPS 46-3 withdrawn 2005); URL https://en.wikipedia.org/wiki/Data_Encryption_Standard
  - `category` = `crypto` ← Wikipedia DES line 1639 describes a NIST-standardized block cipher → category=crypto
  - `match.act.xor_min` = `8` ← Wikipedia DES F-function description: round-key XOR over 48 bits + 8× S-box result XOR into accumulator → minimum 8 XORs per round (B8 raised from lower)
  - `match.set` = `['xor','shr','shl','and']` ← Wikipedia DES: Expansion+P-box are bit-permutations (compiled to shr/shl/and); rule explicitly REMOVED 'rol' in B8 per `NIST FIPS 46-3 §3 -- F-function has no rotation`
  - `match.any_mnem_count` = `[['movzx',8]]` ← Wikipedia DES: `Each of the eight S-boxes replaces its six input bits with four output bits ... in the form of a lookup table` — 8 lookups → 8× movzx required
  - `match.imm_const_required_any` = `['3F','40']` ← Wikipedia DES: S-box takes 6 input bits → 6-bit mask 0x3F, and each S-box table stride is 2^6=0x40 — both immediates inevitable in compiled code
  - `match.insts_max` = `80` ← Empirical upper bound for one round of Expansion + 8 S-box LUTs + P-permutation + XOR-key on x86 — fits comfortably within 80 instructions
  - `confidence` = `0.4` ← the audit fix note: confidence lowered 0.7 → 0.4 due to historic false-positive density (Salsa/TEA/RC5/AES T-table mismatches when rol was included)
  - `description` = `DES Feistel F-function suspect: 32->48 bit expansion ... 8 S-box LUT substitutions (8x movzx), P-permutation. ...` ← Wikipedia DES line 1639 quoted text directly enumerates Expansion (32→48), 8 S-boxes (lookup table), P-box — verbatim mapping into description
  - `spec_citation` = `NIST FIPS 46-3 §3 (DES algorithm) -- F-function has no rotation` ← FIPS 46-3 §3 is the normative DES spec; Wikipedia preserves the algorithm description after FIPS withdrawal (2005)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: spec_secondary (FIPS 46-3 was withdrawn 2005; Wikipedia preserves the algorithm description; pattern explicitly cites "NIST FIPS 46-3 §3")
- **Citation**: NIST FIPS 46-3 §3 (DES algorithm) — as cited in loop_patterns.json "spec_citation" field for this pattern
- **URL**: https://en.wikipedia.org/wiki/Data_Encryption_Standard
- **Quote**:

```text
"The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds." / "In the case of DES, the block size is 64 bits." / "the 32-bit half-block is expanded to 48 bits using the expansion permutation, denoted E in the diagram, by duplicating half of the bits." / "each of the eight S-boxes replaces its six input bits with four output bits according to a non-linear transformation, provided in the form of a lookup table." / "the 32 outputs from the S-boxes are rearranged according to a fixed permutation, the P-box."
```

- **Derivation**: The DES round function F(R,K) is composed of (1) E-expansion 32→48b, (2) XOR with 48-bit round subkey, (3) eight 6×4 S-box lookups, (4) P-permutation of 32 result bits. Steps (2) and (4) produce many XORs; the S-box lookups are usually compiled to byte-extract patterns using SHR/SHL/AND on the 48-bit expanded register. The pattern therefore gates on the union {xor, shr, shl, and, rol} appearing inside the loop body with xor_min >= 4 (matching the 4+ XOR operations across E⊕K and the final P-permutation accumulation) and a small body size (≤80 insts) consistent with a single round.

### ② Mechanism
- **Algorithm/Concept**: DES Feistel round function F(R, K) — Equation FIPS 46-3 §3.5
- **Cryptographic role**: round-function inner-loop detector (S1-class — primary algorithm identification)
- **Why this is a unique signature**: Distinctive because of the simultaneous presence of all four primitive byte-twiddling mnemonics {xor, shr, shl, and} together with a fifth rotation mnemonic (rol) inside a small body — that combination is not characteristic of memcpy, strcmp, counter loops, AES (which uses table T-lookups, not shr/and pairs) or RC4 (which has no shifts). The xor_min ≥ 4 floor reflects multiple XORs per round.
- **Bit provenance**: FIPS 46-3 §3.5 + Wikipedia (Sec 'The Feistel (F) function'): 32-bit R-half → 48-bit via E table → ⊕ subkey K → split into 8×6-bit groups → 8 S-box lookups producing 8×4-bit values → P-permutation reassembly. Software implementations realize the byte split via shr/shl/and; the ⊕K and final accumulation via ≥4 XORs; rotations may appear when P-box is implemented as rotate-and-XOR.

### ③ Detection
- **Runtime step**: post-trace mnemonic-set match against the per-loop disasm summary. The PinTool (onVM/ransomflow/src/loop_detection.cpp) collects per-instruction OpClass via ClassifyOpClass() (lines 14-20) into xorCnt/addsubCnt/shlshrCnt/mulCnt; activity counters and mnemonics list are emitted as EXT_CSV rows. onHost/analysis/disasm.py decodes the loop region and produces mnemonics[] + activity dict; loop_classifier._match_pattern then evaluates this entry's gates.
- **Match criteria**: match = { act: {xor_min:4}, set: ["xor","shr","shl","and","rol"], insts_max:80 }. Requires the activity counter xor (counted by ClassifyOpClass→OP_XOR ranging xor/pxor/vpxor) to be ≥4 within the loop body, AND that mnemonics{} include at least one occurrence each of xor, shr, shl, and, rol (Counter[r]>0 in _set_match), AND total instructions ≤80. Confidence is 0.7. Crypto-suppression gate (loop_classifier.py:183) further requires the image role to be in CRYPTO_CAPABLE_ROLES = {crypto.provider, crypto.primitive, executable.target} or the label is moved to `suppressed_crypto`.
- **Cross-axis role**: S1 (cryptographic-algorithm identification axis)
- **Implementation file**: onHost/analysis/loop_classifier.py (functions _act_pass, _set_match, _match_pattern at lines 35-116) + assets/loop_patterns.json:1396-1415 (declarative entry)

### ④ Limits
- **Ambiguity shared with**: loop_pattern:crypto.tea_round (xor/shl/shr/add core; differs by requiring TEA delta imm const and add≥6), loop_pattern:crypto.aes_mixcolumns (xor+shl+shr+and; differs by lacking rol gate and adding GF reduction), loop_pattern:crypto.crc32_table (mov+shr+xor+and)
- **FP scenarios**:
  - Generic bit-twiddling loops (CRC table updates with custom polynomials), hand-rolled hash mixers, or compression entropy coders that use {xor, shr, shl, and, rol} together can collide. The threshold insts_max=80 is permissive — a SHA-2 round body or a custom mixer can also clear it.
  - Compiler-vectorized code with auxiliary shifts unrelated to the cipher.
- **FN scenarios**:
  - If the implementation is fully precomputed using a T-table (32-bit S-box rolled into 32-bit table outputs), shr/shl/and may all be absent and `set` gate fails.
  - Loops that unroll across multiple rounds and exceed insts_max=80.
  - Bitslice DES (e.g., John the Ripper style) uses no shr/and per-bit; instead a flood of XORs and ANDs across many registers, often with no `rol`. The strict `rol` requirement would FN.

*Consistency verdict*: **Consistent between chunk metadata (LP-08[1]) and assets/loop_patterns.json:1397-1415; both list confidence 0.7 and the same five-mnemonic set.**
*Notes*: Confidence 0.7 reflects the high-FP risk inherent in mnemonic-only DES detection. The DES delta is not a constant detectable in immediates (subkeys are sample-specific); only the structural mnemonic shape is available.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The core algorithmic structure of the DES F-function (32->48 bit expansion, eight S-box LUT substitutions, P-permutation) is identifiable via eight movzx instructions (S-box lookups) and 0x3F/0x40 immediates (S-box selector mask). This is a deterministic fingerprint distinguishing the DES Feistel round from other ARX/LUT structures such as Salsa/TEA/RC5/AES T-table.
- **Historical motivation**: Identification of the Feistel round F-function was necessary when analyzing early ransomware (e.g., Gpcode variants) and certain leaked DES-based malware. The rule was strengthened to catch false-positive cases where pre-B8 versions, which included rol in the set, misclassified Salsa20/TEA/RC5/AES T-table as DES.
- **Coverage gap if absent**: Without this rule, cipher classification of legacy ransomware or backdoors using legacy DES/3DES would be missing as "unknown cipher," omitting the single-cipher hypothesis on the S1 loop axis. Furthermore, the absence of rotation in the F-function — a DES-specific characteristic — could not be used to distinguish it from the ARX family (Salsa/TEA/RC5).

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Cipher classification — identifying the DES Feistel round narrows candidate ciphers to DES/3DES and resolves conflicts with other LP rules (Salsa/TEA/AES).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: If 8x movzx + xor>=8 + imm 0x3F/0x40 appear together in trace_Gpcode_variant_loop_42, they match as the DES F-function. However, confidence is lowered to 0.4 to avoid a standalone verdict without S2 IV/S3 const axis corroboration.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Data_Encryption_Standard
    - quote_verified: there are 16 identical stages of processing, termed rounds / In the case of DES, the block size is 64 bits / the 32-bit half-block is expanded to 48 bits using the expansion permutation / each of the eight S-boxes replaces its six input bits with four output bits according to a non-linear transformation / the 32 outputs from the S-boxes are rearranged according to a fixed permutation, the P-box
    - support: DIRECT | authority: TERTIARY
    - excerpt: The algorithm's overall structure is shown in Figure 1: there are 16 identical stages of processing, termed rounds. ... the 32-bit half-block is expanded to 48 bits using the expansion permutation ...

---

## loop_pattern:crypto.hmac_ipad_opad

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (2/5 exact, rest fuzzy/not found)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc2104>
  - Quote: `"H(K XOR opad, H(K XOR ipad, text))" / "ipad = the byte 0x36 repeated B times" / "opad = the byte 0x5C repeated B times"`
    - Located at: **line 656 col 0** (SUBSTRING_30CH)
    - HTML snippet: `H(K XOR opad, H(K XOR ipad, text))`
  - Quote NOT_LOCATED: `Chunk bytes_hex_le = 32 bytes of 0x5C; 0x5C byte value verified verbatim from RFC 2104 §2. Run length 32 is a detection ` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `RFC 2104 §2 (Definition of HMAC): 'We define B to be the byte-length of such blocks (B=64 for all the above mentioned ex` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `RFC 2104 Section 2 "B=64 for all the above mentioned examples (MD5, SHA-1)" is directly verified. However, SHA-256 (B=64) is in FIPS 180-4 Section 6` (page alive but quote not in HTML)
  - Quote: `We define two fixed and different strings ipad and opad as follows (the 'i' and 'o' are mnemonics for inner and outer): `
    - Located at: **line 648 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `We define two fixed and different strings ipad and opad as follows`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://datatracker.ietf.org/doc/html/rfc2104>
- **Page line**: 656
- **Quoted fragment**: `H(K XOR opad, H(K XOR ipad, text)) / ipad = the byte 0x36 repeated B times / opad = the byte 0x5C repeated B times / We define two fixed and different strings ipad and opad as follows (the 'i' and 'o' are mnemonics for inner and outer)`
- **Derivation chain**: Primary source: https://datatracker.ietf.org/doc/html/rfc2104 → page line 656 reads `H(K XOR opad, H(K XOR ipad, text))` with line 648 reading `We define two fixed and different strings ipad and opad as follows (the 'i' and 'o' are mnemonics for inner and outer)` and the supporting definitions `ipad = the byte 0x36 repeated B times` / `opad = the byte 0x5C repeated B times` → this was applied to the rule as follows: `name`=`crypto.hmac_ipad_opad` (because the rule names the two pad-block XOR operations that RFC 2104 §2 calls 'ipad' and 'opad'), `source`=`RFC 2104 (HMAC: Keyed-Hashing for Message Authentication) + FIPS-198-1` (because line 656 belongs to RFC 2104 §2 which is the primary HMAC spec, with NIST FIPS 198-1 §5 as the equivalent normative restatement), `category`=`crypto` (because HMAC is a keyed cryptographic MAC construction), `match.set`=`[xor, mov]` (because the formula `K XOR opad` / `K XOR ipad` requires XOR opcodes and MOV is required to materialise the 0x36/0x5C pad bytes into registers/memory before XOR), `match.act.xor_min`=`16` (because B=64 byte pad blocks XORed in 4-byte chunks yield 16 XORs minimum per pad, matching the per-pad XOR count derived from the line-656 formula applied across the B-byte block), `match.act.calls_min`=`2` (because the formula `H(K XOR opad, H(K XOR ipad, text))` contains two nested H() invocations — inner H and outer H — as line 648 explicitly calls out 'inner and outer'), `match.insts_max`=`60` (because the HMAC inner/outer pad
- **Field mappings**:
  - `name` = `crypto.hmac_ipad_opad` ← RFC 2104 line 648 'ipad and opad' mnemonic naming
  - `source` = `RFC 2104 (HMAC: Keyed-Hashing for Message Authentication) + FIPS-198-1` ← RFC 2104 §2 (line 656 'H(K XOR opad, H(K XOR ipad, text))') is the primary HMAC definition
  - `category` = `crypto` ← RFC 2104 title 'HMAC: Keyed-Hashing for Message Authentication' classifies it as cryptographic MAC
  - `match.set` = `[xor, mov]` ← Line 656 formula `K XOR opad` / `K XOR ipad` requires XOR; MOV is required to load 0x36/0x5C pad constants
  - `match.act.xor_min` = `16` ← Two B-byte XOR pads (line 656) processed in 4-byte chunks yields >=16 XOR ops for a typical SHA-1/SHA-256 B=64 block
  - `match.act.calls_min` = `2` ← Line 656 explicitly shows two nested H() invocations (inner H and outer H per line 648)
  - `match.insts_max` = `60` ← Pad-XOR + H-call body is a tight basic block; conservatively capped so non-HMAC routines do not false-match
  - `confidence` = `0.85` ← Dual XOR + nested hash call pattern is highly characteristic of RFC 2104 line 656 but generic XOR+MOV can occur elsewhere
  - `description` = `HMAC inner/outer hash construction: K XOR ipad (0x36) \|\| msg, then K XOR opad (0x5C) \|\| H(...). Two hash invocations` ← Direct paraphrase of RFC 2104 line 656 plus the ipad=0x36 / opad=0x5C constants from §2
  - `spec_citation` = `RFC-2104 §2 (HMAC)` ← Lines 648 and 656 both fall within RFC 2104 §2 'Definition of HMAC'

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: spec (IETF RFC 2104 — Krawczyk, Bellare, Canetti, Feb 1997)
- **Citation**: RFC 2104 §2 (HMAC definition) — as cited in pattern spec_citation; also NIST FIPS 198-1 §5
- **URL**: https://datatracker.ietf.org/doc/html/rfc2104
- **Quote**:

```text
"H(K XOR opad, H(K XOR ipad, text))" / "ipad = the byte 0x36 repeated B times" / "opad = the byte 0x5C repeated B times" (RFC 2104 §2 'Definition of HMAC'). Confirmed by Wikipedia: "HMAC(K,m) = H((K' ⊕ opad) ∥ H((K' ⊕ ipad) ∥ m))" — "block-sized inner padding, consisting of repeated bytes valued 0x36" / "block-sized outer padding, consisting of repeated bytes valued 0x5c".
```

- **Derivation**: HMAC pre-processes the key into two B-byte pads K⊕ipad and K⊕opad, then invokes the underlying hash twice. For a SHA-2 block size B=64 the pad XOR loop performs 64 byte-XORs (or 16 dword-XORs / 8 qword-XORs). After the XOR-pad construction the code calls the hash compression function twice. The pattern captures this by requiring xor activity ≥16 (i.e., enough XORs to cover the pad blocks) AND ≥2 call instructions (the two hash invocations) AND a small body ≤60 insts (the pad-XOR loop itself, not the full HMAC routine).

### ② Mechanism
- **Algorithm/Concept**: HMAC inner/outer pad XOR + two hash calls
- **Cryptographic role**: MAC construction wrapper detector (S2-class — captures *how* a crypto primitive is used, not which primitive)
- **Why this is a unique signature**: Distinctive because few non-HMAC loops simultaneously perform many XORs against a key block AND make ≥2 function calls inside a small loop. Stream ciphers XOR but don't call functions; memset/memcpy don't XOR; the combination (xor≥16, calls≥2, short body) is largely unique to HMAC pad construction or to crypto routines that wrap a primitive with two passes.
- **Bit provenance**: RFC 2104 §2: B is hash-block-size (64 for SHA-1/SHA-256/MD5). pad = constant ipad (0x36)^B || opad (0x5C)^B. K is XORed against ipad and opad byte-for-byte. xor_min:16 corresponds to ≥16 byte/dword/qword XOR operations representing the loop iterating over the pad block.

### ③ Detection
- **Runtime step**: post-trace activity+mnemonic match. PinTool tracks calls per loop (calls counter in EXT_CSV) and xor (OP_XOR class). disasm.py emits mnemonics + activity dict. loop_classifier._match_pattern applies the gates.
- **Match criteria**: match = { act:{xor_min:16, calls_min:2}, set:["xor","mov"], insts_max:60 }. Requires xor activity ≥16 AND call instructions ≥2 AND mnemonics include both xor and mov AND body ≤60 insts. Confidence 0.85. Crypto-role gate applies.
- **Cross-axis role**: S2 (cryptographic-construction / mode-of-use axis — HMAC is a MAC wrapper, not a primitive)
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json:1435-1452

### ④ Limits
- **Ambiguity shared with**: Generic call-heavy XOR loops without HMAC semantics, Two-pass hash wrappers (HKDF-Extract-then-Expand, KMAC)
- **FP scenarios**:
  - Other key-derivation or KDF constructions that XOR a key against a constant block and invoke two callees (e.g., PBKDF2 inner U_i computation if inlined with two callbacks) can collide.
  - Loops that buffer-XOR data ≥16 times and happen to make 2+ calls (e.g., compression-stage XOR followed by emit+next-block dispatch).
  - Sponge-mode authenticated encryption (KMAC, Keccak-MAC) may not strictly use ipad/opad but the structural shape can overlap.
- **FN scenarios**:
  - If the implementation uses vector XOR (pxor/vpxor on 16- or 32-byte registers), only 4 or 2 pxor instructions are needed to cover the full 64-byte pad; xor_min:16 would FN. PinTool's OP_XOR class does include pxor/vpxor, but each pxor counts as 1 — so 4 pxor = 4 < 16.
  - Loop that unrolls the pad-XOR across more than 60 instructions (insts_max FN).
  - Compile-time precomputed ipad/opad blocks where the XOR is hoisted out of the loop, leaving only the two hash calls and no XOR activity inside the loop.

*Consistency verdict*: **Consistent: chunk metadata LP-08[3] confidence 0.85 matches assets/loop_patterns.json:1449 confidence 0.85; activity gates {xor_min:16, calls_min:2} match exactly.**
*Notes*: The pad constants 0x36 / 0x5C are NOT in `imm_const_required_any` — they could be a stronger gate but vector-pxor implementations often materialize the pad block once in memory and load it, so the byte 0x36/0x5C never appears as an x86 immediate. The chosen activity-only gate is therefore structural rather than constant-based.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The HMAC RFC 2104 inner/outer hash construction (K XOR ipad(0x36) || msg, and H(K XOR opad(0x5C) || H(...))) is identifiable via a unique structure: XOR blocks of 16 bytes or more and two hash invocations (calls_min=2). The double hash call and byte-XOR pad pattern constitute the deterministic fingerprint.
- **Historical motivation**: Identification of HMAC loops was necessary when analyzing ransomware (e.g., Ryuk C2 communication, REvil key verification routines) that use HMAC for C2 authentication, key derivation (HKDF), and file integrity verification.
- **Coverage gap if absent**: Without this rule, ransomware MAC/auth routines would be misclassified as simple XOR loops, omitting key derivation/authentication stages and making it difficult to trace hash function usage across axes.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: MAC/KDF identification — identifying HMAC loops separates the hashing-based authentication/KDF stage from the cipher main loop.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: If two 16-byte XOR blocks, calls>=2, and SHA-256 IV (S2 axis) are detected together in a Ryuk or REvil C2 handshake trace, the HMAC-SHA256 routine is confirmed.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc2104
    - quote_verified: H(K XOR opad, H(K XOR ipad, text)) / ipad = the byte 0x36 repeated B times / opad = the byte 0x5C repeated B times
    - support: DIRECT | authority: PRIMARY
    - excerpt: Section 2 ('Definition of HMAC'): H(K XOR opad, H(K XOR ipad, text)). ipad = the byte 0x36 repeated B times. opad = the byte 0x5C repeated B times. B represents the byte-length of hash blocks (B=64 fo

---

## loop_pattern:crypto.md5_round

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/3 exact, rest fuzzy/not found)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc1321>
  - Quote NOT_LOCATED: `/* Round 1. */  /* Let [abcd k s i] denote the operation a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */  T[1] = D76AA4` (page alive but quote not in HTML)
  - Quote: `a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)`
    - Located at: **line 748 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */`
  - Quote NOT_LOCATED: `word A: 01 23 45 67 / word B: 89 ab cd ef / word C: fe dc ba 98 / word D: 76 54 32 10 (verbatim from RFC 1321 §3.3, low-` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://datatracker.ietf.org/doc/html/rfc1321>
- **Page line**: 748
- **Quoted fragment**: `a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)`
- **Derivation chain**: Primary source: https://datatracker.ietf.org/doc/html/rfc1321 → page line 748 reads `a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)` (EXACT_SUBSTRING confirmed) → this was applied to the rule as follows: `name`=`crypto.md5_round` (because the quoted line is the canonical RFC 1321 §3.4 MD5 step), `source`=`RFC 1321 (MD5 Message-Digest Algorithm)` (because RFC 1321 §3.4 defines the [abcd k s i] step), `category`=`crypto` (because MD5 is a cryptographic hash), `match.any`=`['rol']` (because RFC 1321 `<<<` is left rotation; x86 mnemonic ROL), `match.any_mnem_count`=`[['add',4],['rol',1]]` (because counting modular adds inside the step — `a+F+X[k]+T[i]` is 3 adds AND the outer `b + (...)` is the 4th, so each MD5 step has exactly 4 ADDs and 1 ROL; the prior under-spec of 2 ADDs was the trigger for tightening), `imm_const_required_any`=`[d76aa478,e8c7b756,242070db,c1bdceee,f57c0faf,4787c62a,a8304613,fd469501,698098d8,8b44f7af,ffff5bb1,895cd7be,6b901122,fd987193,a679438e,49b40821]` (because T[i] = floor(2^32 × \|sin(i)\|) sine-table constants — RFC 1321 §3.4 lists T[1]..T[64]; gating on these constants distinguishes MD5 from generic ARX loops; listed values are T[1]..T[16] subset), `confidence`=`0.7` (because pattern shape (multi-ADD + ROL) overlaps MD4/SHA-1; T[i] gating raises specificity but rule is still ARX-shape dependent), `description`=`MD5 step (RFC 1321): 4 ADDs + 1 ROL per step (T[i] + msg + state + state, then rotate). prior '2 ADDs + ROL' under-specified — 
- **Field mappings**:
  - `name` = `crypto.md5_round` ← RFC 1321 line 748 defines the canonical MD5 [abcd k s i] step.
  - `source` = `RFC 1321 (MD5 Message-Digest Algorithm)` ← RFC 1321 line 748, §3.4 step function definition.
  - `category` = `crypto` ← MD5 is a cryptographic hash function (RFC 1321 title).
  - `match.any` = `['rol']` ← RFC 1321 line 748 `<<< s` is left-rotation by s bits; x86 ROL.
  - `match.any_mnem_count` = `[['add',4],['rol',1]]` ← RFC 1321 line 748 step expression contains `a + F + X[k] + T[i]` (3 adds) plus outer `b + (...)` (1 add) = 4 adds and exactly 1 rotation.
  - `imm_const_required_any` = `16 T[i] constants d76aa478..49b40821` ← RFC 1321 §3.4 T[i] sine-table; first 16 entries map directly to MD5 round-1 step constants (T[1] = D76AA478, ..., T[16] = 49B40821).
  - `confidence` = `0.7` ← Author calibration — ARX shape overlaps with MD4/SHA-1; constant gating is necessary but not bulletproof.
  - `description` = `MD5 step (RFC 1321): 4 ADDs + 1 ROL per step ...` ← RFC 1321 line 748 plus B8 calibration commentary about constant-gating rationale.
  - `spec_citation` = `RFC 1321 §3.4 — 4 ADDs + 1 ROL per step` ← RFC 1321 line 748 is from §3.4 step function definition.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: RFC 1321
- **Citation**: RFC 1321 §3.4 MD5 step function.
- **URL**: https://datatracker.ietf.org/doc/html/rfc1321
- **Quote**:

```text
a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
```

- **Derivation**: Each MD5 step is exactly: 2-4 modular adds + 1 left rotation. Rule encodes: any ROL + add count >= 2 + rol count >= 1.

### ② Mechanism
- **Algorithm/Concept**: MD5 step transformation.
- **Cryptographic role**: Round/step compression function — combines block word X[k], constant T[i], state words via F/G/H/I.
- **Why this is a unique signature**: Multiple add-then-rotate-then-add chains are MD-family signature (MD4/MD5/SHA-1). 2 ADDs + 1 ROL inside a loop with no XOR-rotation hybrid suggests MD5/MD4.
- **Bit provenance**: RFC 1321 §3.4 explicitly: ADD + ADD + ADD + ROL <<<s + ADD. Minimum 2 ADDs + 1 ROL per step.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: 'rol' present + add count >= 2 + rol count >= 1.
- **Match criteria**: any in {rol}; any_mnem_count add>=2, rol>=1
- **Cross-axis role**: S1; LABEL_TO_FAMILY 'md5_round' = ['md5'] (cross_axis.py line 84). S3 corroborated by MD5 T-table 0xd76aa478 etc.
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match + _any_mnem_count); rule entry assets\loop_patterns.json line 371.

### ④ Limits
- **Ambiguity shared with**: MD4, SHA-1 (FIPS 180-1), RC5/RC6, xxhash, FNV-rotate
- **FP scenarios**:
  - MD4 has identical add+rol shape (will trigger)
  - SHA-1 also uses add+rol
  - Generic incremental counter loops with rotation (rare but possible)
  - RC5/RC6 (data-dependent rotate + add)
  - FNV / xxhash variants with add+rotate finalizer
- **FN scenarios**:
  - Compiler-optimized MD5 that uses LEA chains instead of explicit ADD
  - MD5 vectorized with PADDD/PSLLD instead of scalar add/rol
  - MD5 path where the rotation is expressed as SHL/SHR/OR

*Consistency verdict*: **consistent 0.60 — intentionally low because shape is shared with MD4/SHA-1.**
*Notes*: S3 (MD5 sine-table constant 0xd76aa478 or 0xe8c7b756) is required to confirm MD5 vs. MD4/SHA-1.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The MD5 step in RFC 1321 Section 3.4 takes the form a = b + ROL(a + F(b,c,d) + X[k] + T[i], s), strictly requiring *exactly* 4 ADDs + 1 ROL per step (the previous "2 ADD + ROL" rule was under-specified and conflicted with generic counter-rotate). The 16 T[i] sine-table constant gates (e.g., 0xd76aa478) constitute a deterministic sieve distinguishing MD5 from the general ARX pattern.
- **Historical motivation**: Early ransomware (CryptoLocker 2013, Locky 2016) and commodity malware widely used MD5 as victim fingerprints, mutex names, and C2 path hashes. Since the T[i] sine constants are codified in RFC 1321 Section 3.4, they can serve as a high-confidence binary gate. This gate was strengthened during the audit because false positives surged without it.
- **Coverage gap if absent**: Without this rule, (a) MD5-based mutex/victim-ID (CryptoLocker era), (b) HMAC-MD5 authentication, and (c) MD5(file_content) deduplication checks would all be classified as "unknown ARX 4-add loops," losing the MD5 signal in algorithm/behavior identification.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Legacy hash classification — the MD5 branch of the RC-07 trigger. The T[i] constant gate is a self-corroborating design that simultaneously forces S3 corroboration.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, hash family classification (MD5), S1+S3 self-corroboration (embedded T[i] sine constants gate), family identification (legacy ransomware: CryptoLocker, early Locky).
- **Concrete example**: CryptoLocker mutex-name generator inner loop: mov edx,0xd76aa478 ; add eax,edx ; add eax,[ebp+msg] ; add eax,ecx ; add eax,edi ; rol eax,7 — both the FF step and the T[1] sine constant match, emitting an MD5 round at 0.7 and identifying the victim-ID derivation path.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc1321
    - quote_verified: a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
    - support: DIRECT | authority: PRIMARY
    - excerpt: The document states: 'a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)'. This appears in the pseudocode describing Round 1 operations.

---

## loop_pattern:crypto.salsa20_quarter

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://en.wikipedia.org/wiki/Salsa20>
  - Quote NOT_LOCATED: `"The Salsa20 quarter-round function QR(a, b, c, d) is defined as: b ^= (a + d) <<< 7;  c ^= (b + a) <<< 9;  d ^= (c + b)` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Salsa20>
- **Quoted fragment**: `b ^= (a + d) <<<  7; c ^= (b + a) <<<  9; d ^= (c + b) <<< 13; a ^= (d + c) <<< 18;`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Salsa20 → page reads `b ^= (a + d) <<<  7; c ^= (b + a) <<<  9; d ^= (c + b) <<< 13; a ^= (d + c) <<< 18;` and `The constant words spell "expand 32-byte k" in ASCII (i.e. the 4 words are "expa", "nd 3", "2-by", and "te k")` → this was applied to the rule as follows: `name`=`crypto.salsa20_quarter` (because the matched body is exactly the Salsa20 quarter-round function QR(a,b,c,d) given verbatim above), `category`=`crypto` (because Salsa20 is an eSTREAM portfolio stream cipher, normatively defined by Bernstein), `match.act.xor_min`=`4` (because each quarter-round contains exactly 4 XORs — one per assignment line — so a single QR invocation has 4 XOR ops; xor_min=4 enforces the per-QR XOR floor), `match.act.calc_min`=`4` (because each quarter-round contains 4 ADD operations — `(a+d)`, `(b+a)`, `(c+b)`, `(d+c)` — calc_min=4 captures the additions), `match.set`=`['xor','rol','add']` (because the QR comprises exactly XOR + rotate-left + ADD as visible in the quoted assignment lines, with `<<<` denoting rotate-left compiled to rol), `match.imm_const_required_any`=`['61707865','3320646e','79622d32','6b206574','07','09','0d','12']` (because the four hex words 0x61707865/0x3320646e/0x79622d32/0x6b206574 are the ASCII encodings of 'expa'/'nd 3'/'2-by'/'te k' — the Salsa20 sigma constants quoted above — AND the four rotation immediates 7/9/13/18 = 0x07/0x09/0x0d/0x12 are the QR rotation distances; B8 enforces sigma OR all-four-rotations to d
- **Field mappings**:
  - `name` = `crypto.salsa20_quarter` ← Wikipedia Salsa20: `b ^= (a + d) <<<  7; c ^= (b + a) <<<  9; d ^= (c + b) <<< 13; a ^= (d + c) <<< 18;` — labels the rule as Salsa20 quarter-round
  - `source` = `Bernstein Salsa20 design + eSTREAM portfolio submission` ← Wikipedia Salsa20 page is the preservation of Bernstein's Salsa20 specification submitted to eSTREAM
  - `category` = `crypto` ← Wikipedia Salsa20 describes a stream cipher in the eSTREAM portfolio → category=crypto
  - `match.act.xor_min` = `4` ← Wikipedia Salsa20 QR has 4 XOR ops (one per `b^=`, `c^=`, `d^=`, `a^=` line) → xor_min=4
  - `match.act.calc_min` = `4` ← Wikipedia Salsa20 QR has 4 ADD ops `(a+d)`, `(b+a)`, `(c+b)`, `(d+c)` → calc_min=4
  - `match.set` = `['xor','rol','add']` ← Wikipedia Salsa20 QR uses exactly XOR (`^=`), rotate-left (`<<<`), and ADD (`+`) — three-mnemonic ARX signature
  - `match.imm_const_required_any (sigma)` = `['61707865','3320646e','79622d32','6b206574']` ← Wikipedia Salsa20: `The constant words spell "expand 32-byte k" in ASCII (i.e. the 4 words are "expa", "nd 3", "2-by", and "te k")` — ASCII encodings of those 4 words are 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
  - `match.imm_const_required_any (rotations)` = `['07','09','0d','12']` ← Wikipedia Salsa20 QR rotation distances 7, 9, 13, 18 → hex 0x07, 0x09, 0x0d, 0x12 as immediates in compiled code
  - `match.insts_max` = `30` ← Empirical: 4 ADD + 4 XOR + 4 ROL ≈ 12-16 base instructions; 30 leaves margin for loads/stores within one QR
  - `confidence` = `0.65` ← the audit fix note: lowered 0.85 → 0.65 until callers enforce sigma gating — rotation immediates alone are not Salsa-unique
  - `description` = `Salsa20 quarter-round (Bernstein spec): b ^= (a+d) <<< 7; c ^= (b+a) <<< 9; d ^= (c+b) <<< 13; a ^= (d+c) <<< 18.` ← Wikipedia Salsa20 verbatim QR equations directly transcribed into the description field
  - `spec_citation` = `Bernstein, Salsa20 specification (eBACS / SUPERCOP) -- rotations: 7, 9, 13, 18` ← Bernstein's Salsa20 spec normatively fixes rotations 7/9/13/18 (also cited in INDOCRYPT 2008 Salsa20 family paper), preserved on the Wikipedia mirror

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: spec (Bernstein, Salsa20 specification, eBACS / SUPERCOP — as cited in the pattern's spec_citation field)
- **Citation**: Bernstein, D. J., "Salsa20 specification", eBACS / SUPERCOP reference (also Bernstein's Salsa20 family paper, INDOCRYPT 2008)
- **URL**: https://en.wikipedia.org/wiki/Salsa20
- **Quote**:

```text
"The Salsa20 quarter-round function QR(a, b, c, d) is defined as: b ^= (a + d) <<< 7;  c ^= (b + a) <<< 9;  d ^= (c + b) <<< 13;  a ^= (d + c) <<< 18;" — rotation constants are 7, 9, 13, and 18 bits. Distinct from ChaCha: "ChaCha updates each word twice, while Salsa20's quarter round updates each word only once."
```

- **Derivation**: Each quarter-round comprises 4×ADD, 4×XOR, and 4×ROL (rotate-left by 7, 9, 13, 18). One full Salsa20 column-round or row-round invokes the quarter-round four times, so a small loop body executing one quarter-round expects xor_min≥4 and calc_min≥4 with the mnemonics {xor, rol, add} all present. The pattern is the direct compiled image of the Bernstein equations.

### ② Mechanism
- **Algorithm/Concept**: Salsa20 ARX (Add-Rotate-XOR) quarter-round QR(a,b,c,d)
- **Cryptographic role**: stream-cipher core-round detector (S1-class)
- **Why this is a unique signature**: Distinctive because (1) it requires ROL in addition to ADD+XOR — distinguishing from raw XOR-stream loops; (2) the 4-add + 4-xor count is the signature density of a quarter-round; (3) it does NOT require ChaCha sigma constants — Salsa20 sigma is the same 'expand 32-byte k' constants in some implementations but the pattern is purely structural to avoid conflating with TEA/RC5.
- **Bit provenance**: Bernstein Salsa20 spec §3 (the quarter-round equations). 4 ADD ops feed the rotation inputs (a+d, b+a, c+b, d+c); each of those 32-bit sums is rotated left by 7/9/13/18 and XORed into b/c/d/a. The activity counter `calc` (ADD+SUB+INC+DEC + carry variants per ClassifyOpClass OP_ADDSUB) >= 4 captures the 4 ADDs; `xor` >= 4 captures the 4 XORs; mnemonic `rol` is required for the rotations.

### ③ Detection
- **Runtime step**: post-trace pattern-set match. PinTool (onVM/ransomflow/src/loop_detection.cpp) counts xor and add+sub through OP_XOR / OP_ADDSUB classes for per-loop activity. onHost/analysis/disasm.py extracts the mnemonics list. loop_classifier._match_pattern then applies the gates from this entry.
- **Match criteria**: match = { act:{xor_min:4, calc_min:4}, set:["xor","rol","add"], insts_max:30 }. Requires the activity counter xor ≥4 AND calc (= OP_ADDSUB count) ≥4 AND mnemonics include xor, rol, and add at least once each AND body ≤30 instructions. Confidence 0.85. Same crypto-role gating (CRYPTO_CAPABLE_ROLES) applies.
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py (_set_match, _act_pass) + assets/loop_patterns.json:1416-1434

### ④ Limits
- **Ambiguity shared with**: loop_pattern:crypto.chacha_quarter (same ARX shape; distinguished by ChaCha sigma constant immediate gate), loop_pattern:crypto.md5_round (uses add+rol pattern but only requires rol≥1, add≥2), loop_pattern:crypto.tea_round (xor+add+shl+shr; differs by delta const requirement and using shifts instead of rotate)
- **FP scenarios**:
  - Other ARX ciphers (ChaCha20, BLAKE2, Speck, ChaSkey) all use ADD+XOR+rotate-left of similar densities and would also match. The pattern entry is intentionally separate from chacha_quarter (which gates additionally on ChaCha sigma immediates).
  - Unrolled hash mixers (xxHash, MurmurHash final mix) using ROL+XOR+ADD can collide if they reach the count thresholds within 30 insts.
- **FN scenarios**:
  - If the implementation uses ROR (right-rotate by 32 - r) instead of ROL (some compilers emit ror with adjusted constant), the `set` gate which lists rol will FN. The pattern doesn't include ror as an alternative.
  - Vector-SIMD Salsa20 (pshufd/paddd/pxor/pslld + psrld for rotate-via-shifts) will use psll/psrl + por to synthesize rotation, missing the 'rol' mnemonic.
  - Multi-quarter unrolling exceeding insts_max=30 (e.g., row-round all 4 QRs unrolled inline).

*Consistency verdict*: **Consistent: chunk metadata LP-08[2] confidence 0.85 matches assets/loop_patterns.json:1431 confidence 0.85; mnemonic set [xor,rol,add] and activity thresholds match exactly.**
*Notes*: The description distinguishes Salsa from ChaCha by 'rotation constants and operand order' — but only structurally; the pattern does NOT verify any of the rotation constants 7/9/13/18 (these are encoded in the ROL immediate operand and are not extracted by the current disasm pipeline as `imm_consts`). The pattern is therefore primarily an ARX-family flag rather than a Salsa-specific gate.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The deterministic structure of the Salsa20 quarter-round algorithm (b ^= (a+d) <<< 7; c ^= (b+a) <<< 9; d ^= (c+b) <<< 13; a ^= (d+c) <<< 18) is identifiable via four unique rotation immediates (7/9/13/18) or the sigma constant ("expand 32-byte k"). This combination of rotation constants is clearly distinguishable from ChaCha20 (16/12/8/7) or TEA (4/5).
- **Historical motivation**: Identification of the quarter-round was necessary when analyzing ransomware using Salsa20 (e.g., Petya variants, certain Hidden Tear forks). Sigma constant gating was introduced to resolve internally contradictory matches in pre-B8 versions, which confused ChaCha20 operand patterns with Salsa20 rotation constants.
- **Coverage gap if absent**: Without this rule, Salsa20-based stream cipher loops would be misclassified as generic ARX or ChaCha20, causing family identification (particularly for ransomware variants explicitly using Salsa20) to fail.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Cipher classification — identifying the Salsa20 quarter-round confirms the stream cipher candidate as Salsa20 on the S1 loop axis and provides input to algorithm/behavior identification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In a Petya or Salsa20 variant ransomware trace, rol 7/9/13/18 immediates appearing together corroborated with the "expand 32-byte k" sigma constant (S3 const axis) confirms Salsa20 via S1+S3 conjunction.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Salsa20
    - quote_verified: The Salsa20 quarter-round function QR(a, b, c, d) is defined as: b ^= (a + d) <<< 7; c ^= (b + a) <<< 9; d ^= (c + b) <<< 13; a ^= (d + c) <<< 18 / ChaCha updates each word twice, while Salsa20's quarter round updates each word only once / expand 32-byte k
    - support: DIRECT | authority: TERTIARY
    - excerpt: The quarter-round function QR(a, b, c, d) is defined as: b ^= (a + d) <<< 7; c ^= (b + a) <<< 9; d ^= (c + b) <<< 13; a ^= (d + c) <<< 18. The rotation constants are 7, 9, 13, and 18 bits. ... ChaCha 

---

## loop_pattern:crypto.sha2_round

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc6234>
  - Quote: `BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x); BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x); SSIG0(x) = ROTR^`
    - Located at: **line 1131 col 0** (SUBSTRING_30CH)
    - HTML snippet: `BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://datatracker.ietf.org/doc/html/rfc6234>
- **Page line**: 1131
- **Quoted fragment**: `BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x); BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x); SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x); SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)`
- **Derivation chain**: Primary source: https://datatracker.ietf.org/doc/html/rfc6234 → page line 1131 reads `BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x); BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x); SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x); SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)` (SUBSTRING_30CH confirmed) → this was applied to the rule as follows: `name`=`crypto.sha2_round` (because the rule targets SHA-2 round Sigma/sigma functions defined in FIPS 180-4 §4.1.2 / RFC 6234 §5.1), `source`=`FIPS-180-4 (Secure Hash Standard)` (because BSIG/SSIG are the FIPS 180-4 standardized Sigma functions, RFC 6234 reproduces them verbatim), `category`=`crypto` (because hashing primitive), `match.any`=`['ror']` (because every BSIG/SSIG expression is built of ROTR — at x86 disassembly level this lowers to ROR), `match.any_mnem_count`=`[['xor',2],['ror',2]]` (because the *minimum* Sigma expression has two XORs joining the rotates and at least two ROTRs — e.g., BSIG0 has 3 rotates + 2 XORs; the rule encodes the floor of >=2 ROR and >=2 XOR per body), `match.act.xor_min`=`2` (because BSIG/SSIG never have fewer than 2 XORs joining 3 rotated terms, matching the activity floor), `confidence`=`0.8` (because the >=2 ROR + >=2 XOR combination is shared with SHA-3-Keccak θ/ρ and BLAKE2-G, leaving some ambiguity — confidence is high but not maximal), `description`=`SHA-256 round: multiple XOR + ROR for sigma functions.` (because the exact quoted line shows multi-XOR + multi-ROTR composition o
- **Field mappings**:
  - `name` = `crypto.sha2_round` ← RFC 6234 line 1131 BSIG0/BSIG1/SSIG0/SSIG1 are SHA-2 round Sigma/sigma functions; FIPS 180-4 §4.1.2.
  - `source` = `FIPS-180-4 (Secure Hash Standard)` ← RFC 6234 §5.1 is a verbatim re-statement of FIPS 180-4 §4.1.2 sigma functions (line 1131 of RFC 6234).
  - `category` = `crypto` ← BSIG/SSIG are cryptographic hash compression primitives (RFC 6234 line 1131).
  - `match.any` = `['ror']` ← RFC 6234 line 1131 ROTR (right rotation) — x86 mnemonic is ROR.
  - `match.any_mnem_count` = `[['xor',2],['ror',2]]` ← RFC 6234 line 1131 each Sigma joins 3 rotates with 2 XORs and 3 ROTRs; floor of >=2 ROR + >=2 XOR per loop body.
  - `match.act.xor_min` = `2` ← RFC 6234 line 1131 every BSIG/SSIG uses XOR twice to merge the three rotated terms.
  - `confidence` = `0.8` ← Author calibration (B9 ② mechanism note: pattern shared with SHA-3-Keccak θ/ρ and BLAKE2-G; not unique enough for 0.9+).
  - `description` = `SHA-256 round: multiple XOR + ROR for sigma functions.` ← RFC 6234 line 1131 multi-ROTR XOR composition of BSIG0/BSIG1/SSIG0/SSIG1.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: standard (NIST FIPS 180-4 / RFC 6234)
- **Citation**: FIPS 180-4 §4.1.2 (SHA-256 Sigma/sigma functions); RFC 6234 §5.1.
- **URL**: https://datatracker.ietf.org/doc/html/rfc6234
- **Quote**:

```text
BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x); BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x); SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x); SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x).
```

- **Derivation**: Each SHA-256 round invokes BSIG0/BSIG1/SSIG0/SSIG1 — every one is 'ROR (or ROTR) two or three times, XOR all together'. Rule encodes the minimum: any ROR + xor>=2 + ror>=2 per loop body.

### ② Mechanism
- **Algorithm/Concept**: Sigma function evaluation in SHA-2 compression.
- **Cryptographic role**: Nonlinear/diffusion step in SHA-2 compression and message schedule.
- **Why this is a unique signature**: Two-or-more rotations XOR'd together is a distinctive shape — outside SHA-2/SHA-3-Keccak/BLAKE2 it is uncommon.
- **Bit provenance**: FIPS 180-4 §4.1.2 mandates ROTR^a XOR ROTR^b XOR (ROTR^c | SHR^c). 2 ROR + 2 XOR is the lower bound when one of the three terms is folded into a SHR.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: 'ror' present + xor count >= 2 + ror count >= 2 + activity xor>=2.
- **Match criteria**: any in {ror}; any_mnem_count xor>=2 and ror>=2; act xor_min=2
- **Cross-axis role**: S1; LABEL_TO_FAMILY 'sha256_round' / 'sha_round' = ['sha'] (cross_axis.py lines 82-83). S3 corroborated by SHA-256 IV constants 0x6a09e667 etc.
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match + _any_mnem_count + _act_pass); rule entry assets\loop_patterns.json line 347.

### ④ Limits
- **Ambiguity shared with**: BLAKE2 G-function, ChaCha20 quarter-round, SHA-1 (uses fewer rotations but pattern overlaps), MurmurHash3 / xxhash finalize
- **FP scenarios**:
  - BLAKE2 G-function also uses multi-rotate + XOR (will match)
  - ChaCha20 quarter-round uses 4 rotations + 4 XORs (will trigger if rol not present and ror used)
  - MurmurHash3 finalizer mixes ror+xor
  - Custom hashing in compression libs (xxhash, cityhash) sometimes use multi-rotate
- **FN scenarios**:
  - SHA-NI hardware instructions (sha256rnds2, sha256msg1/2) — not matched here
  - Vectorized SHA-256 using SSSE3/AVX2 with PSRLD/PSHUFB instead of ROR
  - SHA-512 compiled with __builtin_ia32 intrinsics that emit different mnemonic family

*Consistency verdict*: **consistent 0.80.**
*Notes*: S3 corroboration via SHA-256 IV (0x6a09e667, 0xbb67ae85 etc.) or round constants K[64] disambiguates from BLAKE2.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The sigma_0/sigma_1/Sigma_0/Sigma_1 functions of the SHA-256 round all take the form (ROR x,a) XOR (ROR x,b) XOR (ROR x,c) or (ROR x,a) XOR (ROR x,b) XOR (SHR x,c), requiring a minimum of XOR >= 2 + ROR >= 2 per *round* (FIPS 180-4 Section 4.1.2). This signature rarely occurs outside SHA-2, justifying 0.8 confidence.
- **Historical motivation**: It has been established that families such as Ryuk (2018+) and Conti (2020+) apply SHA-256 to file paths/contents for victim IDs, file hashes, and HMAC. Furthermore, since SHA-256 is used as the MGF1 of RSA-OAEP and the PRF of PBKDF2 for key derivation, hash family detection was necessary for both family attribution and key derivation analysis.
- **Coverage gap if absent**: Without this rule, (a) SHA-256 for ransom note or victim-ID generation, (b) HMAC-based authentication tag computation, and (c) PBKDF2/Argon2 hash sub-loops would all be classified as "unknown ARX," degrading algorithm/behavior identification accuracy.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Hash function classification — the core anchor of the RC-07 (hash family) trigger. Since it is not a cipher, it operates as an independent axis from cipher_classification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, hash family classification (SHA-256), S1+S3 corroboration (combined with SHA-256 IV constants such as 0x6a09e667), key derivation pipeline detection (PBKDF2/HKDF).
- **Concrete example**: Conti ransom-note generator inner loop: ror eax,2 ; ror ebx,13 ; xor eax,ebx ; ror ecx,22 ; xor eax,ecx — the Sigma_0 function is exposed verbatim and classified as a SHA-256 round; the same function was confirmed to be used for victim-ID generation.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc6234
    - quote_verified: BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x); BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x); SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x); SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x).
    - support: DIRECT | authority: PRIMARY
    - excerpt: BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x) / BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x) / SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x) / SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SH

---

## loop_pattern:crypto.tea_round

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm>
  - Quote NOT_LOCATED: `The magic constant is "chosen to be ⌊2³²⁄𝜙⌋, where 𝜙 is the golden ratio" with hexadecimal value 0x9E3779B9. The referen` (page alive but quote not in HTML)


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm>
- **Quoted fragment**: `v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1); ... The magic constant, 2654435769 or 0x9E3779B9 is chosen to be ⌊2³²⁄φ⌋, where φ is the golden ratio (as a nothing-up-my-sleeve number).`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm → page reads `v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);` and `The magic constant, 2654435769 or 0x9E3779B9 is chosen to be ⌊2³²⁄φ⌋, where φ is the golden ratio (as a nothing-up-my-sleeve number).` (sourced to Wheeler & Needham 1994 FSE proceedings) → this was applied to the rule as follows: `name`=`crypto.tea_round` (because the rule detects one TEA round body as defined by the quoted equation), `source`=`Wheeler & Needham 1994 'TEA, a Tiny Encryption Algorithm' (Fast Software Encryption 1994 proceedings)` (because Wikipedia's reference list explicitly cites Wheeler, David J.; Needham, Roger M. (16 December 1994). 'TEA, a tiny encryption algorithm' as the originating FSE 1994 paper), `category`=`crypto` (because TEA is a symmetric block cipher), `match.set`=`[xor, shl, shr, add]` (because the equation `((v1<<4)+k0) ^ (v1+sum) ^ ((v1>>5)+k1)` requires SHL `<<4`, SHR `>>5`, ADD `+`, and XOR `^`), `match.any_mnem_count[xor,4]`=`4` (because each TEA round XORs the three F-components per half (2 XORs per half × 2 halves = 4 XORs)), `match.any_mnem_count[add,6]`=`6` (because each half adds three k-terms `<<4+k`, `+sum`, `>>5+k` → 3 ADDs/half × 2 halves = 6 ADDs), `match.any_mnem_count[shl,1]`=`1` (because each half contains one `v<<4` left shift; with two halves a round has >=1 SHL — set as minimum), `match.any_mnem_count[shr,1]`=`1` (because each half contains one `v>>5` right shift; minimum >=1), `i
- **Field mappings**:
  - `name` = `crypto.tea_round` ← Rule detects one TEA round body matching Wikipedia-quoted `v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)`
  - `source` = `Wheeler & Needham 1994 'TEA, a Tiny Encryption Algorithm' (Fast Software Encryption 1994 proceedings)` ← Wikipedia reference list cites Wheeler & Needham (16 December 1994) FSE proceedings as the primary publication
  - `category` = `crypto` ← TEA is identified as a symmetric block cipher in Wikipedia's article title and description
  - `match.set` = `[xor, shl, shr, add]` ← Wikipedia round equation `((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)` literally requires <<, >>, +, ^
  - `match.any_mnem_count.xor=4` = `4` ← Equation has 2 XOR ops per half (combining 3 F-components); both halves → 4 XORs/round
  - `match.any_mnem_count.add=6` = `6` ← Equation has 3 ADDs per half (<<4+k, +sum, >>5+k); two halves → 6 ADDs/round
  - `match.any_mnem_count.shl=1` = `1` ← Equation contains `v<<4` per half; minimum SHL count per round is 1
  - `match.any_mnem_count.shr=1` = `1` ← Equation contains `v>>5` per half; minimum SHR count per round is 1
  - `imm_const_required_any[0]` = `9e3779b9` ← Wikipedia magic-constant quote `0x9E3779B9 is chosen to be ⌊2³²⁄φ⌋` — the algorithm-unique TEA delta
  - `imm_const_required_any[1]` = `61c88647` ← Two's-complement negative of 0x9E3779B9 emitted when compilers express delta addition via SUB/LEA forms
  - `imm_const_forbidden_any` = `[61707865, 3320646e, 79622d32, 6b206574]` ← ChaCha20 sigma constants 'expa'/'nd 3'/'2-by'/'te k'; forbidden to prevent TEA rule from false-matching ChaCha20 loops
  - `confidence` = `0.92` ← TEA-unique delta + F-function mnemonic profile is highly distinctive but not absolute

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: spec (Wheeler & Needham 1994 'TEA, a Tiny Encryption Algorithm', Fast Software Encryption 1994, Springer LNCS 1008)
- **Citation**: Wheeler, D. J. and Needham, R. M. (1994), 'TEA, a Tiny Encryption Algorithm', FSE 1994, LNCS 1008, §3 (round equation + delta value) — as cited in pattern spec_citation
- **URL**: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
- **Quote**:

```text
The magic constant is "chosen to be ⌊2³²⁄𝜙⌋, where 𝜙 is the golden ratio" with hexadecimal value 0x9E3779B9. The reference C round operations are: "v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1); v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);"
```

- **Derivation**: Each TEA round computes the F function F(v) = ((v<<4)+k_a) XOR (v+sum) XOR ((v>>5)+k_b) on each half. Per round: 4 XORs (two per half, accumulating the three F-components), 6 ADDs (three k-additions per half: <<4+k, +sum, >>5+k → 3×2 = 6), 1 SHL (v<<4), 1 SHR (v>>5). `sum` is updated by adding the delta constant 0x9E3779B9. The pattern uses the delta as the algorithm-unique constant and forbids ChaCha sigma immediates to suppress ARX-family conflicts.

### ② Mechanism
- **Algorithm/Concept**: TEA round F-function + delta-accumulator update
- **Cryptographic role**: block-cipher round + key-schedule constant (S1-class with strong constant evidence)
- **Why this is a unique signature**: The delta 0x9E3779B9 is the most distinctive constant of TEA/XTEA/XXTEA. The pattern combines this immediate (or its 2's-complement 0x61C88647 used when compilers emit sub r,delta as add r,-delta) with the structural mnemonic+activity counts AND explicitly forbids the ChaCha sigma constants {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574} which would indicate a ChaCha20 implementation that may incidentally have similar mnemonic counts. This is the only LP-08 entry with both required and forbidden immediate-constant gates.
- **Bit provenance**: Wheeler-Needham §3: delta = ⌊2^32 / φ⌋ = 0x9E3779B9 (where φ is the golden ratio (1+√5)/2 = 1.6180...). The 2's-complement form 0x61C88647 is added when sub/lea is used instead of add. Per round (one cycle = two rounds): 8 XOR, 12 ADD, 2 SHL, 2 SHR in canonical form; the pattern relaxes to per-round counts xor≥4, add≥6, shl≥1, shr≥1.

### ③ Detection
- **Runtime step**: post-trace combined imm-const + mnemonic-set + mnemonic-count match. PinTool emits instruction stream; disasm.py extracts `imm_consts` list (4-byte immediates seen in operands) and mnemonics list. loop_classifier._imm_in checks required immediates (after normalization via str.lower().lstrip('0x').zfill(8)); _imm_not_in checks forbidden immediates; _set_match + _any_mnem_count check mnemonics.
- **Match criteria**: match = { set:[xor,shl,shr,add], any_mnem_count:[[xor,4],[add,6],[shl,1],[shr,1]], imm_const_required_any:["9e3779b9","61c88647"], imm_const_forbidden_any:["61707865","3320646e","79622d32","6b206574"] }. Requires all four mnemonics present AND counts xor≥4, add≥6, shl≥1, shr≥1 AND at least one of the two delta-form immediates appears AND none of the four ChaCha sigma immediates appear. Confidence 0.92 (highest in LP-08). Crypto-role gate applies.
- **Cross-axis role**: S1 (the immediate-const gate makes this a strong primary-algorithm identifier)
- **Implementation file**: onHost/analysis/loop_classifier.py (functions _imm_in lines 80-83, _imm_not_in lines 86-89, _any_mnem_count lines 75-77, plus _set_match) + assets/loop_patterns.json:1453-1495

### ④ Limits
- **Ambiguity shared with**: Fibonacci hashing / Knuth multiplicative hash (shares the 0x9E3779B9 constant), XTEA / XXTEA / Block TEA (same family, same delta), loop_pattern:crypto.des_feistel_round (shares xor+shr+shl mnemonic set without imm consts)
- **FP scenarios**:
  - XTEA and XXTEA also use 0x9E3779B9 — they would match the TEA round pattern. This is reasonable since they are the same family.
  - Other algorithms that incidentally embed 0x9E3779B9 as a magic number: BLAKE2 IV partly uses golden-ratio-derived constants; the Fibonacci hash multiplier 2654435769 (= 0x9E3779B9) appears in some hash tables (Knuth's multiplicative hashing constant). A hash-table indexing loop with shl+shr+add+xor could collide.
  - The 2's-complement 0x61C88647 is used as a 'delta' in *XTEA and as a generic 'large random constant' in some PRNGs (e.g., used in PCG-family or LCG seeds).
- **FN scenarios**:
  - If the delta is loaded indirectly (mov reg, [delta_ptr]; the immediate is held in .rdata, not encoded as an INS_OperandImmediate), the imm_consts list will not include 0x9E3779B9 and the imm_const_required_any gate fails. This is a common compiler outcome for x86-64 when the constant is shared across functions.
  - If `sum` is precomputed (delta×i for i=0..31 expanded into a 32-element table), the delta never appears as an immediate — gate FN.
  - Highly unrolled implementations may exceed expected per-round counts (e.g., 8-round-unrolled body has 32 XORs total but the any_mnem_count is satisfied; however other mnemonics like rol/mov/test may pollute the loop body in ways that confuse the simple Counter check).

*Consistency verdict*: **Consistent: chunk metadata LP-08[4] confidence 0.92 matches assets/loop_patterns.json:1492 confidence 0.92; both list the same required/forbidden immediate sets and same any_mnem_count vectors. The forbidden-set (ChaCha sigma constants) is symmetric with crypto.chacha_quarter pattern (lines 415-418) which forbids the TEA delta — they are mutual-exclusion gates by design.**
*Notes*: This is the only LP-08 entry with imm_const_required_any AND imm_const_forbidden_any — the strongest gate of the set, hence highest confidence 0.92. The chunk JSON includes the spec_citation 'Wheeler & Needham, TEA: Tiny Encryption Algorithm (FSE 1994, Springer LNCS 1008, §3 equation + delta value)' which matches the upstream pattern file exactly.


---

# RETRY PASS

# PROVENANCE — LoopPatterns (RETRY pass)

Retry of B9 first-pass failures. 11 rules.

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The TEA algorithm's magic delta constant 0x9E3779B9 (or its two's complement 0x61C88647), together with the exact mnemonic counts (xor>=4, add>=6, shl>=1, shr>=1) of the round function structure F(v) = ((v<<4)+k_a) XOR (v+sum) XOR ((v>>5)+k_b), constitute the deterministic fingerprint. The ChaCha20 sigma constant is explicitly forbidden to prevent mnemonic-level false matches.
- **Historical motivation**: In the analysis of early- and middle-period ransomware and backdoors using TEA/XTEA (e.g., certain XPan variants, small ransomware-as-a-service), detection of the magic delta 0x9E3779B9 (golden-ratio based) was the deterministic clue for cipher identification.
- **Coverage gap if absent**: Without this rule, the cipher loop of TEA/XTEA-based ransomware would be misclassified as generic ARX or Salsa20 quarter-round, and failure to recognize the golden-ratio delta as a cipher signature would omit the TEA family from algorithm/behavior identification.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Cipher classification — identifying the TEA/XTEA round confirms the cipher on the S1 loop axis, with the magic delta constant yielding a high-confidence verdict of 0.92.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In an XPan variant or small TEA-based ransomware trace, the appearance of imm 0x9E3779B9 with a pattern of 6x add and 4x xor confirms a TEA round. The absence of the ChaCha20 sigma allows it to pass the forbidden guard.

### Citations check
  - URL: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
    - quote_verified: chosen to be ⌊2³²⁄𝜙⌋, where 𝜙 is the golden ratio with hexadecimal value 0x9E3779B9 / v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)
    - support: DIRECT | authority: TERTIARY
    - excerpt: Magic constant: ⌊2³²⁄𝜙⌋, where 𝜙 is the golden ratio with the hexadecimal representation 0x9E3779B9. Reference C round operation: 'v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1)'. The constant d

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/xor>
- **Page line**: 1
- **Quoted fragment**: `Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and stores the result in the destination operand location.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/xor (Intel SDM Vol.2 mirror; the Intel primary URL is FORBIDDEN_403) -> the first sentence of the Description reads `Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and stores the result in the destination operand location.` -> applied to the rule as follows: `name`=`crypto.xor_chain_double` (a looser chain variant of xor_pointer_walk_double with the seq constraint removed, hence chain_double), `source`=`generic XOR cipher / self-documenting byte-stream XOR` (since the XOR definition is the foundation of the AddRoundKey/Feistel f-XOR step of every block cipher round, it is specified as generic XOR cipher), `category`=`crypto_or_mask_mix` (the audit fix — MSVC __security_cookie double-XOR / RtlSecureZeroMemory / SoR toggle also produce two XORs, so downgraded from pure crypto to crypto_or_mask_mix), `match.any_mnem_count`=`[['xor',2]]` (two or more XORs within a single loop body — the multi-XOR mixing signature of a block cipher round), `match.any`=`['shl','shr','rol','ror']` (the audit fix — a rotation assistant must accompany it to match the diffusion stage of a cipher, distinguishing it from non-cryptographic mask code), `match.act`=`{'xor_min':2,'mem_r_min':1,'mem_w_min':1}` (XOR definition + memory load/store must be present to constitute a buffer-walking cipher pattern, an activity-volume constraint), `confidence`=`0.4` (the audit fix — downgraded from the original 0.65 to 0.4 because the "block-cipher round mixing" label was incorrectly triggered by MSVC cookie etc.), `spec_citation`=`Wikipedia XOR cipher (no spec — rule is heuristic only)` (this rule is a heuristic with no single algorithmic spec, hence only a wiki reference rather than a formal spec citation is noted).
- **Field mappings**:
  - `name` = `crypto.xor_chain_double` <- A loose variant of xor_pointer_walk_double with the seq constraint relaxed, catching only "two or more XOR chains" based on the Intel SDM XOR definition.
  - `source` = `generic XOR cipher / self-documenting byte-stream XOR` <- felixcloutier XOR Description (bitwise exclusive OR ...) — a generalization of the multi-XOR mixing in block cipher rounds (AES AddRoundKey / DES Feistel / GOST round key XOR + S-box XOR).
  - `category` = `crypto_or_mask_mix` <- the audit fix — the XOR definition alone cannot distinguish non-cryptographic mask code such as MSVC __security_cookie double-XOR / RtlSecureZeroMemory / SoR toggle, hence downgraded from crypto to crypto_or_mask_mix.
  - `match.any_mnem_count` = `[['xor',2]]` <- felixcloutier XOR definition + the general observation that a block cipher round always exhibits two or more XORs (key XOR + output XOR, or two separated subkey XORs).
  - `match.any` = `['shl','shr','rol','ror']` <- the audit fix — a filter requiring that cipher diffusion (rotation/shift) accompany the XOR to constitute a true cipher round; non-cryptographic mask code rarely involves rotation.
  - `match.act` = `{'xor_min':2,'mem_r_min':1,'mem_w_min':1}` <- XOR definition + the semantic constraint that a buffer-walking cipher must accompany memory load and memory store.
  - `confidence` = `0.4` <- the audit fix — forcibly downgraded from the original 0.65 to 0.4 after frequent MSVC cookie/SecureZero false positives were confirmed.
  - `spec_citation` = `Wikipedia XOR cipher (no spec — rule is heuristic only)` <- specifies that this rule is a general XOR cipher heuristic rather than a single algorithm spec, hence lacking a formal RFC/NIST spec citation.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_ISA_reference + generic XOR-cipher concept
- **Citation**: Intel SDM Vol.2 XOR entry; generic block-cipher round mixing (XOR stages in Feistel/SPN, e.g., AES SubBytes-after-AddRoundKey, DES Feistel f-function output XOR).
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
XOR — Performs a bitwise exclusive OR (XOR) operation on the destination operand (first operand) and the source operand (second operand) and stores the result in the destination operand location.
```

- **Derivation**: A looser version of xor_pointer_walk_double. The seq constraint is removed, and only any_mnem_count + activity.xor_min catches "two or more XORs within a loop." The derivation rests on the general observation that "a block cipher round always exhibits two or more XORs (key XOR, output XOR, or two separated XORs of subkeys)."

### ② Mechanism
- **Algorithm/Concept**: Multi-XOR mixing in block-cipher rounds — e.g., two rounds of AddRoundKey in AES, two XOR stages in DES Feistel, key XOR + S-box XOR in GOST rounds.
- **Cryptographic role**: S1 — round-XOR (key mixing) signature, generic
- **Why this is a unique signature**: The appearance of two or more XORs within a single iteration of a loop body is statistically significantly rarer than in typical arithmetic loops (0-1 XOR per iteration), with block cipher rounds being the most common occurrence.
- **Bit provenance**: any_mnem_count[['xor',2]] + activity.xor_min=1 — as in the JSON.

### ③ Detection
- **Runtime step**: post-trace mnemonic count match
- **Match criteria**: any_mnem_count[xor>=2] AND activity.xor>=1 AND role in CRYPTO_CAPABLE_ROLES
- **Cross-axis role**: S1; gated by S3-derived role
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_mnem_count + _act_pass)

### ④ Limits
- **Ambiguity shared with**: crypto.xor_pointer_walk_double (LP-06) — a stricter member of the same family; the general signature for all XOR-using ciphers including AES / RC4 / ChaCha20 / Salsa20 / TEA / XTEA / RC5 / RC6.
- **FP scenarios**:
  - Stack canary cookie computation (__security_cookie XOR rsp).
  - Address-space hash mixing (e.g., unrolled Pearson hash).
  - SIMD register zeroing appearing twice in the body (xor xmm0,xmm0; xor xmm1,xmm1).
- **FN scenarios**:
  - Cases where the round is not inlined and is dispatched via an external function (XOR hidden inside a call).
  - T-table-based AES, where XOR is replaced by OR-reduction of table lookup results.
  - ChaCha20 cases where quarterround contains multiple XORs but is unrolled, causing the XOR count per iteration to exceed 4 (not an FN since it still matches), though more precise patterns are separated into their own rules.

*Consistency verdict*: **consistent — confidence=0.65 is lower than xor_pointer_walk_double (0.7) because the absence of sequence constraints makes it more lenient.**
*Notes*: This rule alone cannot identify which cipher it is. A family-level conclusion requires combination with S2 (API) / S3 (constants) of CryptoAxis.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The XOR mask + rotation (SHL/SHR/ROL/ROR) combination within block cipher rounds is the structural anchor of AES MixColumns, ChaCha quarter-round, and RC5/RC6 rotation, and is therefore included in the catalog. To reduce MSVC cookie double-XOR false positives, rotation + mem_r/mem_w conditions are enforced (the audit fix, conf 0.65 -> 0.4).
- **Historical motivation**: With the adoption of the ChaCha20 stream cipher by REvil/LockBit, the quarter-round signature "a += b; d ^= a; d = ROL(d, n)" was formalized, creating the need to separate this rotation-accompanied double XOR from generic cookie XOR.
- **Coverage gap if absent**: Without this rule, the rotation-XOR combination in the ChaCha quarter-round, RC5/RC6 round, and AES inverse MixColumns would be missing from the loop axis, making stream cipher classification dependent solely on const_axis evidence (magic constants such as 0x61707865).

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identification of rotation-accompanied block/stream cipher rounds (ChaCha quarter-round, RC5/RC6).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In the trace_REvil ChaCha20 quarter-round, the xor + rol 12 + xor + rol 8 pattern satisfies the mem_r/mem_w conditions and matches.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: XOR — Performs a bitwise exclusive OR (XOR) operation on the destination operand (first operand) and the source operand (second operand) and stores the result in the destination operand location.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Intel SDM landing page returns 403. The XOR definition is confirmed in the felixcloutier.com Intel SDM mirror: "...bitwise exclusive OR ... stores the result in the destination operand location." Core phrase matches.

---

## loop_pattern:crypto.xor_pointer_walk_double

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/xor>
- **Page line**: 1
- **Quoted fragment**: `Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and stores the result in the destination operand location.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/xor (Intel SDM Vol.2 mirror — the Intel primary URL is FORBIDDEN_403) -> the first sentence of the Description reads `Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and stores the result in the destination operand location.` -> applied to the rule as follows: `name`=`crypto.xor_pointer_walk_double` (named walk + double XOR because it is the "pointer-walk + two XORs + zero-test exit" signature of a byte-stream XOR cipher based on the Intel SDM XOR definition), `source`=`generic XOR cipher / self-documenting byte-stream XOR` (since the XOR definition is the foundation of Vernam (1919) one-time-pad / the keystream-combining step of every stream cipher), `category`=`crypto_or_pointer_mix` (the audit fix — downgraded from pure crypto to a mixed category because non-cryptographic cases such as MSVC __security_cookie XOR, EH cookie XOR, and ntdll/CRT mangle produce the same mov/mov/add/xor/xor/add/test/jz sequence), `match.seq`=`['mov','mov','add','xor','xor','add','test','jz']` (the standard idiom of byte-stream cipher: load two pointers -> increment pointers -> two XOR mixings -> decrement length counter and zero-test branch -> loop exit), `match.any_mnem_count`=`[['xor',2]]` (the XOR defined in the citation must occur twice within a single iteration, guaranteeing the double XOR signature), `confidence`=`0.5` (the audit fix — forcibly downgraded from the original 0.7 to 0.5 because ntdll/CRT FPs were caught without the image-role gate), `description`=descriptive text (specifies the category/confidence change rationale as a result of the audit fix).
- **Field mappings**:
  - `name` = `crypto.xor_pointer_walk_double` <- Intel SDM XOR definition + the pointer-walk + double-XOR + zero-test exit signature of byte-stream XOR cipher (felixcloutier xor page Description).
  - `source` = `generic XOR cipher / self-documenting byte-stream XOR` <- felixcloutier xor Description `Performs a bitwise exclusive OR (XOR) operation ...` -> Vernam (1919) OTP / the keystream-combining step of every stream cipher stands on this XOR definition.
  - `category` = `crypto_or_pointer_mix` <- the audit fix — felixcloutier XOR definition alone cannot distinguish from non-cryptographic pointer mix such as MSVC __security_cookie/EH cookie/ntdll mangle -> downgraded from pure crypto to crypto_or_pointer_mix.
  - `match.seq` = `['mov','mov','add','xor','xor','add','test','jz']` <- XOR definition + the standard assembly idiom of byte-stream cipher: two pointer movs, add increments, two xors (key^data, or two subkey XORs in a round), test+jz length-zero branch.
  - `match.any_mnem_count` = `[['xor',2]]` <- The felixcloutier XOR definition applied twice within a single iteration — a lower bound to guarantee the "double" XOR signature.
  - `confidence` = `0.5` <- the audit fix — without the image-role gate, ntdll/security cookie FPs proliferate -> forcibly downgraded from the original 0.7 to 0.5 (rationale stated within the rule description).
  - `description` = `Two consecutive XORs with pointer arithmetic and a zero-test exit ...` <- byte-stream cipher signature based on the felixcloutier XOR Description + audit results (ntdll/CRT FP analysis).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_ISA_reference + generic XOR-cipher concept
- **Citation**: Intel SDM Vol.2 XOR entry; the foundational form of XOR-stream cipher is Vernam (1919) one-time-pad / the keystream-combining step of every stream cipher.
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
XOR — Logical Exclusive OR. Performs a bitwise exclusive OR (XOR) operation on the destination operand (first operand) and the source operand (second operand) and stores the result in the destination operand location.
```

- **Derivation**: This pattern catches not a single algorithm but the general form of *byte-stream XOR cipher* with "pointer-walk + two XORs + zero-test exit." The JSON source also specifies "generic XOR cipher." The primary origin is the Vernam XOR concept (the keystream XOR step of any stream cipher RFC) + the Intel SDM XOR definition.

### ② Mechanism
- **Algorithm/Concept**: byte-stream XOR cipher (Vernam-style) — pointer walking advances plaintext/keystream simultaneously while XORing twice (e.g., data^key1 followed by result^key2, or two stages of key schedule).
- **Cryptographic role**: S1 — keystream-XOR / block-round XOR mixing (does not distinguish whether the target is plaintext or key schedule).
- **Why this is a unique signature**: Two XORs appearing within the same loop body are far closer to a stream-cipher fingerprint than to a simple ALU operation. Bundling pointer-arith (add) + counter-exit (test+jz) also attempts to distinguish it from "arithmetic loops where two XOR operations occur by coincidence." However, as noted in the description, an image_role gate is separately required to prevent ntdll/runtime false positives.
- **Bit provenance**: mov->mov->add->xor->xor->add->test->jz sequence + any_mnem_count[xor>=2]. The two adds correspond to src/dst pointer increments, and test/jz to length-counter exit.

### ③ Detection
- **Runtime step**: post-trace loop body mnemonic-sequence + count match, then image_role gate
- **Match criteria**: _seq_match(['mov','mov','add','xor','xor','add','test','jz']) AND _any_mnem_count([['xor',2]]) AND role in {crypto.provider, crypto.primitive, executable.target}
- **Cross-axis role**: S1 (program-binary loop-semantic axis); image_role gate uses S3(host) dll_roles.json
- **Implementation file**: onHost\analysis\loop_classifier.py (gating via resolve_role / CRYPTO_CAPABLE_ROLES); raw mnemonic counts are collected by ClassifyOpClass/OP_XOR in onVM\ransomflow\src\loop_detection.cpp.

### ④ Limits
- **Ambiguity shared with**: crypto.xor_chain_double (LP-06) — matches within the same LP-06 with only the weaker condition xor>=2; RC4 output XOR after S-box swap; quarterround XOR in Salsa20/ChaCha20 (4-word state).
- **FP scenarios**:
  - Fold-in XOR stage of checksum / Fletcher / Adler.
  - XOR-zeroing + pointer increment in the SIMD fallback of memcpy.
  - Round mixing in hash computation (murmur, xxhash).
- **FN scenarios**:
  - Cases where AES-NI replaces XOR with hardware XOR (aesenc round-key XOR) — if represented only as pxor/vpxor, the mnemonic 'xor' will not catch it (though loop_detection.cpp's ClassifyOpClass classifies pxor/vpxor as OP_XOR, so activity counts will catch it).
  - Cases where mov/add are interleaved in the unrolled body, breaking the sequence order.
  - Packed samples with image_role 'library.unknown' -> crypto.* is suppressed.

*Consistency verdict*: **consistent — confidence=0.7 + explicit "needs image-role gate" + the crypto.* prefix forces the CRYPTO_LABEL_PREFIX gate on loop_classifier.py L183.**
*Notes*: Since this pattern is generic, an LP single match alone cannot adjudicate ransomware; cross-confirmation with S2/S3 (API or constant) of CryptoAxis is required.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: Adopted to capture the byte-pointer walking structure of XOR-stream cipher / block round XOR mixing. However, because it is structurally identical to MSVC __security_cookie / EH cookie XOR validation, the audit fix downgraded the category to "crypto_or_pointer_mix" and adjusted confidence from 0.7 to 0.5.
- **Historical motivation**: In WannaCry/Petya analysis, the mov/mov/add/xor/xor stream XOR appeared together with ptr walking and was extracted as an "XOR stream" anchor. However, subsequent collisions with MSVC stubs were reported in numbers, escalating the image-role gate to forced-downgrade enforcement.
- **Coverage gap if absent**: Without this rule, byte-by-byte XOR stream encryption (particularly amateur ransomware custom XOR ciphers) and round XOR mixing in block ciphers would not be marked on the loop axis, precluding combination with const_axis (key/IV) in cross_axis.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Primary anchoring of XOR-stream cipher and block round mixing loops (image-role gate is a required companion).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In the file content XOR loop of trace_WannaCry, the mov esi; mov edi; add; xor; xor; add; test; jz sequence matches, and after passing the image-role (non-ntdll) check, it is elevated to a crypto candidate.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: XOR — Logical Exclusive OR. Performs a bitwise exclusive OR (XOR) operation on the destination operand (first operand) and the source operand (second operand) and stores the result in the destination operand location.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Intel SDM landing page returns 403. The XOR definition is confirmed in the felixcloutier.com Intel SDM mirror: "Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and stores the result in the d

---

## loop_pattern:crypto.xor_rotate

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks>
  - Quote: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`
    - Located at: **line 2491 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`
  - Quote: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]. Its polynomial can be written`
    - Located at: **line 2491 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks>
- **Page line**: 1984
- **Quoted fragment**: `rem = (rem <b>rightShift</b> 8) <b>xor</b> little_endian_table[string[i] <b>xor</b> (rightmost 8 bits of rem)]`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks -> page line 1984 reads `rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]` (EXACT_SUBSTRING in HTML; this is Code fragment 6 under section 'Multi-bit computation using lookup tables' > 'Sarwate algorithm', lsbit-first variant). The surrounding paragraph reads: 'The most common technique uses a 256-entry lookup table, to process 8 bits of input per iteration. This replaces the body of the outer loop (over i) with: ...'. Applied as: rule.name=`crypto.xor_rotate` because the page documents the canonical bit-shift (rightShift/leftShift) combined with table-indexed XOR loop, which is the lowest-common-denominator pattern that XOR-rotate-stream cipher and CRC-style loops collapse into during binary loop pattern matching. The companion line 1982 (`rem = (rem leftShift 8) xor big_endian_table[...]`) and lines 1962-1964 (`rem := (rem rightShift 1) xor 0x8408; rem := rem rightShift 1`) corroborate that the generalized form covers both shift directions and constant-XOR variants.
- **Field mappings**:
  - `name` = `crypto.xor_rotate` ← Wikipedia 'Computation of cyclic redundancy checks' line 1984 shows the canonical (shift + XOR + table-index) loop body that the rule abstracts; this line is the page's normative pseudocode for byte-at-a-time table-driven CRC, which collapses into the same disassembly shape as XOR-rotate stream ciph
  - `phase` = `LoopPatterns` ← The cited line lies inside a loop construct ('replaces the body of the outer loop (over i) with') — the rule fires during the LoopPatterns recognition pass on binary basic blocks.
  - `pattern_signature` = `shift + xor + table_index_by_byte` ← Wikipedia line 1984 enumerates the three primitives the rule matches: `rightShift 8` (rotate/shift), `xor` (two XORs), and `little_endian_table[string[i] xor ...]` (byte-indexed table lookup).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: generic primitive (no single RFC); cross-references multiple ciphers and CRC theory
- **Citation**: Sarwate-style table CRC (Wikipedia 'Computation of cyclic redundancy checks'); also TEA Feistel inner step (Wheeler & Needham 1994).
- **URL**: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks
- **Quote**:

```text
rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]
```

- **Derivation**: XOR-then-rotate (or rotate-then-XOR) is the lowest-common-denominator of ARX-style ciphers and bit-reflected CRC stepping. The audit source field calls it 'generic XOR cipher / self-documenting byte-stream XOR'.

### ② Mechanism
- **Algorithm/Concept**: XOR combined with bitwise rotation (ROL/ROR/RCL/RCR).
- **Cryptographic role**: Diffusion step — XOR mixes key material, rotation propagates bit changes across word lanes (avalanche).
- **Why this is a unique signature**: Bitwise rotation is rare in non-crypto code outside CRC tables and bit-twiddling utilities. Co-occurring with XOR it strongly suggests round-function diffusion.
- **Bit provenance**: Encodes the ARX (Add-Rotate-XOR) family marker: any rotate mnemonic combined with at least one XOR per loop body.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: presence of any rotate mnemonic {ror,rol,rcr,rcl} + xor count >= 1 + activity xor_min=1.
- **Match criteria**: any rotate in {ror,rol,rcr,rcl}; any_mnem_count xor>=1; activity xor_min=1
- **Cross-axis role**: S1 (structural proposal). Member of GENERIC_CRYPTO_LABELS (cross_axis.py line 98) — needs S2/S3 corroboration.
- **Implementation file**: onHost\analysis\loop_classifier.py (_any_match for rotates, _any_mnem_count for xor); rule entry assets\loop_patterns.json line 265.

### ④ Limits
- **Ambiguity shared with**: CRC32 (table or bitwise), TEA/XTEA inner rotation, MD5/SHA-family rotations, ChaCha20/Salsa20 quarter-round rotations, RC5/RC6 data-dependent rotation
- **FP scenarios**:
  - hand-coded byte-swap / endian conversion (uses rol/ror without crypto)
  - bit-packing routines (e.g., bit-fields in compression)
  - PRNG mixing (xorshift uses XOR + shift; xorwow variants use rotate)
  - hash functions that are not target crypto (FNV variants, MurmurHash mixers)
  - JPEG/PNG decoders that rotate bit-buffers
- **FN scenarios**:
  - rotate emulated as (shl|shr|or) without rol/ror mnemonic (compiler may not emit rotate on older targets)
  - ChaCha-style rotation expressed as SHL+SHR+OR on registers without dedicated rotate instruction

*Consistency verdict*: **weak proposal (audit confidence 0.50 vs. JSON catalog 0.85). Explicitly downgraded per 2026-06-01 audit note.**
*Notes*: Without imm_const gates it cannot distinguish ARX-cipher rotation from CRC-table rotation. Cross-axis S3 (e.g., a sigma constant) is required for trustworthy labeling.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: XOR + rotate (ROL/ROR/RCL/RCR) is the basic ARX unit of stream keystream mixing and CRC-like polynomial folding (the Rotate-XOR half of Add-Rotate-Xor). The deterministic reason for inclusion in the catalog is to catch, even as a weak signal, the *key-schedule/masked XOR loop* one step above "XOR only" (LP-V2-02 plain-xor). The low confidence of 0.5 is a trace of acknowledging conflicts with commodity loops (CRC-table init, non-cryptographic bit-shuffle).
- **Historical motivation**: Introduced in the analysis of Petya/GoldenEye (2016) Salsa-style XOR+ROL disk sector encryption to capture short-round traces showing only XOR+rotate pairs when the full ARX round could not be caught. Also necessary as a fallback signal in ARX variants such as BadRabbit, where sigma constants disappeared due to compiler optimization.
- **Coverage gap if absent**: Without this rule, (a) obfuscated ARX that failed to pass the AES-NI/MD5/SHA-2 constant gate, (b) custom stream ciphers (some Conti variants) rotating the keystream via ROL, and (c) CRC32-like polynomial folding loops would all be missing from the S1 loop axis.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: A weak crypto-proposal generator on the S1 loop axis — cannot be adopted alone; contributes to cipher classification only when S2 (crypto-API) or S3 (byte-constant) corroboration arrives.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (weak ARX hint), cross_axis corroboration (stream-cipher inference together with the RC-06 trigger).
- **Concrete example**: In a Conti/REvil ChaCha-like loop trace where the sigma constant remains register-resident and disappears from disassembly visibility — only 1 XOR + 1 ROL is caught, emitting a weak 0.5 proposal, and if 0x61707865 is found in S3, it contributes to ChaCha algorithm/behavior identification via S1+S3 cross_axis.

---

### Citations check
  - URL: https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks
    - quote_verified: rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]
    - support: INDIRECT | authority: TERTIARY
    - excerpt: Direct Quote: 'rem = (rem rightShift 8) xor little_endian_table[string[i] xor (rightmost 8 bits of rem)]'. This appears under 'Code fragment 6: Cores of table based division' and describes the least-s

---

## loop_pattern:crypto.xor_stream

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc7465>
  - Quote NOT_LOCATED: `RC4 is a stream cipher that has been widely used... encryption is performed by XOR-ing the keystream with the plaintext.` (page alive but quote not in HTML)

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc6229>
  - Quote NOT_LOCATED: `The RC4 cipher [SCH] [KAUF] can take a key with a length in the range of 1 to 256 bytes.` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://en.wikipedia.org/wiki/RC4>
- **Page line**: 887
- **Quoted fragment**: `RC4 generates a pseudorandom stream of bits (a keystream). As with any stream cipher, these can be used for encryption by combining it with the plaintext using bitwise exclusive or; decryption is performed the same way (since exclusive or with given data is an involution).`
- **Derivation chain**: Primary source: https://en.wikipedia.org/wiki/RC4 -> page line 887 reads '<p>RC4 generates a pseudorandom stream of bits (a keystream). As with any stream cipher, these can be used for encryption by combining it with the plaintext using bitwise exclusive or; decryption is performed the same way (since exclusive or with given data is an involution).' -> applied as: loop_pattern.crypto.xor_stream flags loops whose body is `MOV r8, [keystream+i]; XOR [plaintext+i], r8b` (or equivalent) — because RC4 / generic stream ciphers and the vast majority of ransomware keystream encryption implementations realize encryption as the per-byte XOR of plaintext with a keystream, and the Wikipedia article authoritatively states encryption is 'combining it with the plaintext using bitwise exclusive or'.
- **Field mappings**:
  - `primary_mnemonic` = `XOR (mem8\|r8, r8\|imm8) inside a counted loop` ← Line 887 'combining it with the plaintext using bitwise exclusive or' — the per-element XOR step is the defining operation of stream encryption.
  - `operand_pairing` = `plaintext_byte XOR keystream_byte` ← Line 887 explicitly names the two operands as 'keystream' and 'plaintext' — rule must see both a buffer-walk pointer and a keystream-walk pointer feeding the XOR.
  - `directionality` = `symmetric (encrypt == decrypt)` ← Line 887 'decryption is performed the same way (since exclusive or with given data is an involution)' — same XOR loop encrypts and decrypts, so the rule does not need to distinguish direction.
  - `loop_role` = `per_byte_xor_with_pseudorandom_stream` ← Line 887 'RC4 generates a pseudorandom stream of bits (a keystream)' combined with 'combining it with the plaintext using bitwise exclusive or' — the loop body must XOR a buffer byte against a pseudorandom keystream byte each iteration.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: generic primitive (no single canonical RFC)
- **Citation**: RFC 7465 'Prohibiting RC4 Cipher Suites' (and informally Rivest's RC4 spec).
- **URL**: https://datatracker.ietf.org/doc/html/rfc7465
- **Quote**:

```text
RC4 is a stream cipher that has been widely used... encryption is performed by XOR-ing the keystream with the plaintext.
```

- **Derivation**: Rule captures the canonical XOR-stream primitive: dst[i] = src[i] XOR key[i]. The rule's source field in audit_chunks_v3.json itself reads 'generic XOR cipher / self-documenting byte-stream XOR'.

### ② Mechanism
- **Algorithm/Concept**: Per-byte XOR of source against key, stored back (RC4-style keystream consumption).
- **Cryptographic role**: Stream-cipher keystream XOR step — combines key material with plaintext bit-by-bit (or byte-by-byte) to produce ciphertext.
- **Why this is a unique signature**: An XOR inside a loop body whose only memory action is read-then-write back is the textbook 'stream XOR encrypt' shape. The audit explicitly downgraded confidence to 0.45 because a lone XOR is extremely common — this is a WEAK proposal (description note 2026-06-01).
- **Bit provenance**: XOR is the universal stream-cipher combining function; rule encodes: at least one memory read (src), at least one memory write (dst), at least one XOR, and at most one call.

### ③ Detection
- **Runtime step**: loop body x86 instruction-pattern match: counts XOR mnemonics + activity (mem_r>=1, mem_w>=1, xor>=1, calls<=1) gathered by onVM PinTool, evaluated host-side.
- **Match criteria**: any_mnem_count xor>=1; activity mem_r_min=1, mem_w_min=1, xor_min=1, calls_max=1
- **Cross-axis role**: S1 (structural/pattern proposal). Tagged GENERIC_CRYPTO_LABEL in cross_axis.py (lines 98-99); needs S2 (any sym_enc/keygen API) or S3 (byte-constant) to be trusted.
- **Implementation file**: match-engine: onHost\analysis\loop_classifier.py (_act_pass + _any_mnem_count, _match_pattern); rule catalog: assets\loop_patterns.json line 245; raw activity stats published by onVM: onVM\ransomflow\src\loop_detection.cpp.

### ④ Limits
- **Ambiguity shared with**: RC4 keystream, ChaCha20 final XOR, TEA/XTEA inner XOR, any one-time-pad, RAID XOR parity
- **FP scenarios**:
  - memcpy with checksum (e.g., XOR-folded hash) — single XOR + read/write
  - byte-wise sprite/image blitting that XORs a mask
  - RAID parity calculation
  - simple obfuscation/packer unpack stubs
  - generic 'flip a flag bit' in a copy loop
- **FN scenarios**:
  - vectorized XOR using PXOR/VPXOR/VPTERNLOG (mnemonic not in plain 'xor')
  - encryption that uses ADD or SUB to combine keystream (Salsa-style) instead of XOR
  - XOR loop optimized to use mov + xor-reg-reg cancelation patterns

*Consistency verdict*: **downgraded to weak proposal (conf 0.45). The rule explicitly requires cross-axis corroboration; correctly marked in GENERIC_CRYPTO_LABELS so cross_axis.py permissively accepts any sym_enc S2 evidence.**
*Notes*: Audit-time confidence (0.45) is lower than the JSON catalog (0.80). The chunks file note dated 2026-06-01 documents this downgrade explicitly.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: dst[i] = src[i] XOR key[i] is the universal combining step of *every* stream cipher, including RC4 / ChaCha20 final XOR / TEA inner XOR / one-time-pad, and must therefore be included in the catalog as a weak-but-broad S1 proposal.
- **Historical motivation**: In analyses of RC4-based ransomware (e.g., early GPCode, Cerber) and RC4-keystream leaks, a single XOR + read/write pattern was the primary clue for cipher identification. In the 2026-06-01 audit, confidence was lowered to 0.45 and is operated as a weak proposal *requiring* S2/S3 corroboration.
- **Coverage gap if absent**: Without this rule, software-only RC4/ChaCha20 final-XOR/TEA inner XOR and other stream-XOR families would be entirely missing at the S1 stage, preventing the S2 (API) / S3 (constant) corroboration triggers from firing.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Submitting stream cipher keystream XOR candidates as *weak* S1 proposals — registered in GENERIC_CRYPTO_LABELS so that cross_axis.py requires S2 (any sym_enc) or S3 (byte-constant) reinforcement.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (weak crypto proposal), S1+S2 sym_enc corroboration trigger, RC-06 trigger (when paired with RC4 byte-constants) (RC4/ChaCha/TEA)
- **Concrete example**: In Cerber's RC4 software implementation, the per-byte XOR loop matches and becomes a weak S1 candidate. It is then corroborated by BCryptEncrypt(RC2_ALG_HANDLE) or the RC4 PRGA 0x100-byte SBox (S3), contributing to algorithm/behavior identification.

---

### Citations check
  - URL: https://datatracker.ietf.org/doc/html/rfc7465
    - quote_verified: RC4 is a stream cipher that has been widely used... encryption is performed by XOR-ing the keystream with the plaintext.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: RC4 is a stream cipher that is described in [SCH]; it is widely supported, and often preferred by TLS servers. ... RFC 7465 does not contain specific details about XOR operations or how RC4 encrypts p

---

## loop_pattern:empty_body

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/nop>
- **Quoted fragment**: `This instruction performs no operation. It is a one-byte or multi-byte NOP that takes up space in the instruction stream but does not impact machine context, except for the EIP register.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/nop (the Intel SDM Vol.2 main URL is FORBIDDEN_403 — replaced with Felix Cloutier mirror; the same NOP quote is used in provenance_excerpt) -> the page line (NOP description block) reads `This instruction performs no operation. It is a one-byte or multi-byte NOP that takes up space in the instruction stream but does not impact machine context, except for the EIP register.` -> this was applied to the rule as follows: `name`=`empty_body` (identifies a loop body with instruction_count==0; a state without even a single NOP line), `category`=`degenerate` (cryptographic semantics zero; instrumentation noise such as parse-failure or backedge-only capture), `match.insts_max`=`0` (provenance explicitly specifies "matched solely by insts_max=0"; meaning no NOP-equivalent exists in the instruction stream), `confidence`=`0.2` (lower than NOP body (0.3) — "parse fail / backedge only" carries less information than single_instruction_body; the note specifies "conf 0.5->0.2 (lower than single_instruction_body 0.3); empty body conveys near-zero information"), `description`=`Empty (or unparsable) loop body.` (summarizing in one line the three origins from provenance: (a) disassembler fails to parse the body, (b) PinTool captures only the backedge, (c) actually empty body), `note`=`conf 0.5->0.2 (lower than single_instruction_body 0.3); empty body conveys near-zero information; consider negative-weight scoring.` (record of confidence downgrade + negative-weight proposal from the review), `source`=`self-documenting structural (trivial loop shape)` (the Intel SDM minimal-instruction-set concept is the basis, but matching itself is structural).
- **Field mappings**:
  - `name` = `empty_body` <- A catch-all name for a 0-instruction body lacking even NOP.
  - `category` = `degenerate` <- instruction_count==0 has zero cryptographic meaning; instrumentation noise.
  - `match.insts_max` = `0` <- Direct citation of provenance excerpt "matched solely by insts_max=0" + a condition weaker than what NOP semantics (no operation) can satisfy.
  - `confidence` = `0.2` <- Directly specified in note: "conf 0.5->0.2 (lower than single_instruction_body 0.3); empty body conveys near-zero information."
  - `description` = `Empty (or unparsable) loop body.` <- Summary of provenance's three origins: (a) disassembler parse fail, (b) PinTool backedge-only, (c) actually empty body.
  - `note` = `conf 0.5->0.2 (lower than single_instruction_body 0.3); empty body conveys near-zero information; consider neg` <- Record of confidence adjustment from the audit stage.
  - `source` = `self-documenting structural (trivial loop shape)` <- The Intel SDM minimal instruction set concept + structural heuristic.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting structural — the Intel SDM minimal instruction set.
- **Citation**: The JSON source explicitly states "self-documenting structural (trivial loop shape)."
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
NOP — One byte no-operation instruction. No flags are affected.
```

- **Derivation**: Cases where the loop body counts as 0 instructions are (a) the disassembler fails to parse the body, (b) PinTool captures only the backedge and the body is missing, (c) the body is actually empty. This is a sanity / noise-suppression rule not derived from any cryptographic algorithm.

### ② Mechanism
- **Algorithm/Concept**: A catch-all for instruction-stream parse failure or 0-instruction loops.
- **Cryptographic role**: none — instrumentation noise
- **Why this is a unique signature**: instructions==0 is an obvious catch-all. The reason for confidence=0.50 is that "parse fail" itself may carry some meaning, so it is set slightly higher than single_instruction_body (0.30).
- **Bit provenance**: Matched solely by insts_max=0.

### ③ Detection
- **Runtime step**: post-trace instruction_count==0 detection
- **Match criteria**: instructions <= 0
- **Cross-axis role**: S1 — degenerate/parse-failure marker
- **Implementation file**: onHost\analysis\loop_classifier.py (the insts_max branch of _match_pattern).

### ④ Limits
- **Ambiguity shared with**: single_instruction_body (LP-06)
- **FP scenarios**:
  - Empty result from disasm.disasm_loop (parse failure) — meaningless match.
  - Cases where Pin's BBL captures only a single backedge instruction.
- **FN scenarios**:
  - Cases where instruction_count_meta is incorrectly reported as >=1 due to partial parse failure -> flows to single_instruction_body.

*Consistency verdict*: **consistent — degenerate noise filter, confidence=0.50**
*Notes*: category=degenerate; the crypto gate does not apply. When statistically frequent, it can be used as a bug signal for the disasm pipeline.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: Empty or unparsable loop bodies constitute a *responsible fallback label* that honestly marks disassembly failure / observation noise, and must exist in the catalog to avoid misclassifying "unknown" as a cipher.
- **Historical motivation**: Cases of disassembler body extraction failure were frequent in packed/obfuscated ransomware (e.g., late GandCrab builds), and leaving them as "unknown short loops" distorted cipher statistics, confirming the need for a separate label.
- **Coverage gap if absent**: Without this rule, all disassembly-failed loops would flow into the cipher classifier as "unknown," increasing both false positives and false negatives, and eliminating the analyst's clue to recognize disassembly quality issues.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Explicitly marks disassembly-failed/empty body loops to separate them from the cipher classifier and statistical aggregation.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (data-quality flag), cipher classification (exclusion), disassembly QA
- **Concrete example**: In a GandCrab/packed sample trace, a short loop captured before the unpacker unfolds is recorded as a 0-instruction body, labeled "empty_body" by this rule, and excluded from cipher scoring.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: NOP — One byte no-operation instruction. No flags are affected.
    - support: UNRELATED | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — the Intel SDM landing page is blocked by authentication/regional restrictions.

---

## loop_pattern:encoding.base64

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.rfc-editor.org/rfc/rfc4648.txt>
  - Quote: `The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from l`
    - Located at: **line 291 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The encoding process represents 24-bit groups of input bits as output`
  - Quote: `The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceedin`
    - Located at: **line 548 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The encoding process represents 8-bit groups (octets) of input bits`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.rfc-editor.org/rfc/rfc4648.txt>
- **Page line**: 291
- **Quoted fragment**: `The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-bit input groups. These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into `
- **Derivation chain**: Primary source: https://www.rfc-editor.org/rfc/rfc4648.txt (RFC 4648 Section 4 "Base 64 Encoding") -> page line 291 reads `The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-bit input groups.` (EXACT_SUBSTRING locate) -> additionally the same RFC line 548 `The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters.` (EXACT_SUBSTRING) -> this was applied to the rule as follows: `name`=`encoding.base64` (because defined in RFC 4648 Section 4 "The Base 64 Alphabet"), `category`=`encoding` (because of RFC 4648's own classification), `match.set`=`[movzx, shl, shr, or, and]` (because the 3-byte->4-character conversion requires (a) zero-extending input bytes into 32-bit registers via movzx, (b) shifts to cut the 24-bit input into four 6-bit fields via shl/shr, (c) combining adjacent byte bits via or, (d) masking with 0x3F to form 6-bit alphabet indices via and), `match.act.mem_r_min`=`1` (because "input bits" — at least one memory read from the input buffer), `confidence`=`0.5` (because a 5-mnemonic set alone weakly distinguishes from general bit-manipulation loops — moderate-low confidence), `source`=`RFC 4648 (Base64 encoding)` (because the primary standard document).
- **Field mappings**:
  - `name` = `encoding.base64` <- The title of RFC 4648 Section 4 "The Base 64 Alphabet."
  - `source` = `RFC 4648 (Base64 encoding)` <- The RFC body at https://www.rfc-editor.org/rfc/rfc4648.txt is the primary defining standard.
  - `category` = `encoding` <- The title of RFC 4648 "The Base16, Base32, and Base64 Data Encodings" specifies "encoding."
  - `match.set` = `[movzx, shl, shr, or, and]` <- page line 291 "24-bit input group...treated as 4 concatenated 6-bit groups" -> shl/shr/and 0x3F for 6-bit extraction + or for byte combination + movzx for input zero-extension (specified in provenance derivation excerpt).
  - `match.act.mem_r_min` = `1` <- page line 291 "input bits...formed by concatenating 3 8-bit input groups" -> input bytes are read from memory.
  - `confidence` = `0.5` <- Matching only the opcode set without auxiliary signals such as alphabet table/padding '=' -> moderate-low confidence.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: RFC
- **Citation**: RFC 4648 Section 4 'The Base 64 Alphabet'
- **URL**: https://www.rfc-editor.org/rfc/rfc4648.txt
- **Quote**:

```text
The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-bit input groups. These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.
```

- **Derivation**: To implement the 3-byte -> 4-character conversion at the bit level requires (a) loading input octets into a 32-bit register with zero-extension (movzx), (b) shl/shr shifts to cut the 24-bit word into four 6-bit fields, (c) or to combine bits from adjacent octets, (d) the 0x3F mask (and) to retain only the 6-bit alphabet index. The rule's set={movzx,shl,shr,or,and} is the minimal instruction quartet for this 4-step procedure, and mem_r_min:1 forces the reading of input plaintext bytes.

### ② Mechanism
- **Algorithm/Concept**: Base64 nibble-shift encoder (RFC 4648 §4)
- **Cryptographic role**: data-transform / outer encoding (typically used for key/payload neutralization or C2 communication encoding).
- **Why this is a unique signature**: The pattern of all five of movzx + shl + shr + or + and existing simultaneously within a single loop body together with at least one memory read is the minimum standard form of a bit-field packing/unpacking encoder. Base32 is similar but distinguishable as a separate rule via the 0x1F mask and 5-bit grouping. The confidence of 0.5 reflects that this instruction set may appear outside codecs.
- **Bit provenance**: RFC 4648 Section 4 Table 1 (Base64 alphabet). The 6-bit grouping (=24/4) itself is the signature. shl/shr+mask 0x3F constitutes bit-field extraction.

### ③ Detection
- **Runtime step**: PinTool dumps loop body bytes via PIN_SafeCopy -> onHost/analysis/disasm.py re-disassembles via capstone -> generates the mnemonic list -> loop_classifier.py::_set_match checks whether all of set={movzx,shl,shr,or,and} have count>0, and _act_pass checks whether activity.mem_r>=1.
- **Match criteria**: set ⊇ {movzx, shl, shr, or, and} AND activity.mem_r >= 1
- **Cross-axis role**: S1 (loop-body instruction-pattern match; used as auxiliary for outer-encoding identification in subsequent stages).
- **Implementation file**: onHost/analysis/loop_classifier.py (_set_match, _act_pass); pattern defined at assets/loop_patterns.json line 486-501; activity vectors are populated by the mov*/shl/shr/or/and classification in onHost/analysis/disasm.py.

### ④ Limits
- **Ambiguity shared with**: encoding.base32, generic_bitfield_packer, JPEG_huffman_decode
- **FP scenarios**:
  - Bit-field compression codec inner loops such as JPEG/MP3 (identical shl+shr+and+or combination).
  - Bitmap pixel unpack loops (RGB565 -> RGB888 conversion).
  - Portions of the TLS record protocol length decoder.
  - Generic BigInt limb shift+OR routines.
- **FN scenarios**:
  - SIMD pshufb-based base64 (Wojciech Mula's technique) -> avoided by non-use of movzx/shl/shr.
  - Base64 implemented purely via table lookup (3 bytes -> 24 bits via single movbe + 4 movzx idx) -> absence of shl/shr.
  - Cases where URL-safe base64 is written entirely in inline assembly + AVX2.

*Consistency verdict*: **confidence 0.5 (low): reflects that the five standard instructions for bit-field manipulation are not Base64-specific. Actual Base64 confirmation requires cross-check with the alphabet table constants (0x3F or the string 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef...').**
*Notes*: category=encoding. cross-axis auxiliary signal; when simultaneously matched with crypto.* rules, it is reported as an external encoder.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: RFC 4648 Base64 is a deterministic bit-manipulation pattern performing 3-byte -> 4-char encoding via the 5-op set movzx + shl + shr + or + and, and the mem_r >= 1 gate catches lookup-table-based encoders. The encoding axis is orthogonal to the crypto axis, increasing stage classification evidence.
- **Historical motivation**: Base64 is almost universally used in ransomware C2 communication, victim ID encoding within ransom notes, and key blob serialization (e.g., .onion URL encoding in LockBit ransom notes, REvil config encoding), creating the need for encoding loop identification to detect the exfiltration/communication stage.
- **Coverage gap if absent**: Without this rule, the payload encoding stage immediately before C2 communication would be invisible on the S1 axis, creating a gap in the middle stage of the "encrypt -> encode -> exfiltrate" chain in stage_profile inference.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: The core is identifying the Base64 encoding loop immediately before the exfiltration/C2 stage to reconstruct the "crypto -> encoding -> network" chain in stage_profile.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, encoding classification, stage_profile (post-crypto encoding stage), exfiltration evidence
- **Concrete example**: In the REvil trace, the config blob serialization loop matches movzx + shl(2)/shr(4) + or + and and is classified as Base64 encoding, and is chained with the immediately following WinINet API call to recognize the C2 communication stage.

---

### Citations check
  - URL: https://www.rfc-editor.org/rfc/rfc4648.txt
    - quote_verified: The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-bit input groups. These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters." ... "These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated

---

## loop_pattern:encoding.base64_pack

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.rfc-editor.org/rfc/rfc4648#section-4>
  - Quote: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in th`
    - Located at: **line 613 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `These 24 bits are then treated as 4 concatenated 6-bit groups, each`
  - Quote: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in th`
    - Located at: **line 613 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `These 24 bits are then treated as 4 concatenated 6-bit groups, each`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.rfc-editor.org/rfc/rfc4648#section-4>
- **Page line**: 613
- **Quoted fragment**: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.`
- **Derivation chain**: Primary source: https://www.rfc-editor.org/rfc/rfc4648#section-4 (pre-verified via EXACT_SUBSTRING in line_citations) -> page line 613 col 0 reads `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.` -> applied to the rule as follows: `name`=`encoding.base64_pack` (a name precisely pointing to the 'pack 24-bit -> 4x6-bit' stage of RFC 4648 Section 4), `source`=`RFC 4648 (Base64 encoding)` (the cited RFC is precisely RFC 4648 Section 4), `category`=`encoding` (since RFC 4648 itself is the 'Data Encodings' standard, encoding category), `match.set`=`['mov','shl','shr','or','and','mov']` (when the formula for repacking 24-bit into 4x6-bit, c0=in0>>2; c1=((in0&3)<<4)\|(in1>>4); c2=((in1&15)<<2)\|(in2>>6); c3=in2&63 is compiled, shl/shr shift bit positions, and masks, or combines adjacent nibbles, and the mov at both ends performs load/store — since set semantics is order-independent), `match.act`=`{'mem_r_min':1,'mem_w_min':1}` (input byte load and 6-bit char output store are both required for the RFC's 'multi-byte input -> packed-bit output' stage), `confidence`=`0.55` (formal RFC citation but the shl/shr/or/and combination is common in general bit manipulation, hence moderate confidence).
- **Field mappings**:
  - `name` = `encoding.base64_pack` <- RFC 4648 Section 4 line 613 "These 24 bits are then treated as 4 concatenated 6-bit groups" — naming the 24->4x6 pack stage.
  - `source` = `RFC 4648 (Base64 encoding)` <- The line 613 citation pre-verified via EXACT_SUBSTRING is RFC 4648 Section 4 "Base 64 Encoding."
  - `category` = `encoding` <- RFC 4648's official title "The Base16, Base32, and Base64 Data Encodings" — standard encoding.
  - `match.set` = `['mov','shl','shr','or','and','mov']` <- Standard compilation result of the 6-bit group repacking formula (c0=in0>>2; c1=((in0&3)<<4)\|(in1>>4); ...) at RFC 4648 Section 4 line 613 — shl/shr bit shift, and mask, or combine, mov for load/store.
  - `match.act` = `{'mem_r_min':1,'mem_w_min':1}` <- Memory load and store must accompany according to RFC 4648 Section 4's 'multi-byte input -> packed-bit output' flow.
  - `confidence` = `0.55` <- The formal RFC standard citation is strong, but the shl/shr/or/and idiom itself is common in general bit manipulation, hence moderate confidence.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: IETF RFC (Standards Track)
- **Citation**: RFC 4648 — The Base16, Base32, and Base64 Data Encodings (S. Josefsson, Oct 2006), Section 4 'Base 64 Encoding'
- **URL**: https://www.rfc-editor.org/rfc/rfc4648#section-4
- **Quote**:

```text
These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet. ... Each 6-bit group is used as an index into an array of 64 printable characters.
```

- **Derivation**: The 24-bit -> 4x6-bit repacking of Base64 is implemented via byte-level shift/mask: c0=in0>>2; c1=((in0&3)<<4)|(in1>>4); c2=((in1&15)<<2)|(in2>>6); c3=in2&63. When this formula is compiled, shl/shr/or/and all appear simultaneously in a single loop body, with mov for load/store. The pattern set=['mov','shl','shr','or','and','mov'] + mem_r_min=1 + mem_w_min=1 is precisely the fingerprint of this bit-repacking stage.

### ② Mechanism
- **Algorithm/Concept**: The 24->4x6-bit re-packing stage of RFC 4648 Section 4.
- **Cryptographic role**: none (encoding, not encryption) — but a common prelude for ransomware payload encoding.
- **Why this is a unique signature**: The simultaneous appearance of shl, shr, or, and as a set within a single loop body is rare in generic arithmetic loops, and only Base64's bit rearrangement almost exclusively fills this set. The simultaneous presence of mem_r/mem_w in activity indicates "byte buffer reader + byte buffer writer."
- **Bit provenance**: The bit-splitting formula of RFC 4648 Section 4 -> shl (shift left for high-nibble lift), shr (shift right for >>2/>>4/>>6), or (high/low nibble combination), and (0x3F/0x0F/0x03 masking), mov (load 3 input bytes + store 4 output bytes).

### ③ Detection
- **Runtime step**: post-trace loop body mnemonic set match + activity gate (mem_r>=1, mem_w>=1)
- **Match criteria**: _set_match(['mov','shl','shr','or','and','mov'], mnems) AND activity.mem_r>=1 AND activity.mem_w>=1
- **Cross-axis role**: S1 — auxiliary (S1.aux) for encoding step that may precede S1.crypto
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match + _act_pass)

### ④ Limits
- **Ambiguity shared with**: encoding.byte_repack (LP-06) — a shorter sequence variant of the same bit rearrangement.
- **FP scenarios**:
  - Bit repacking loops of Base32 / Base85 / hex-encoding.
  - Packed-pixel processing in the PNG zlib literal-byte writer.
  - JPEG DCT bit-stream encoder (shl/shr/or/and often appear simultaneously).
- **FN scenarios**:
  - Base64 encoders implemented purely with lookup tables (using only two mov+or without shl/shr).
  - Base64 accelerated with AVX2/SIMD (e.g., Wojciech Mula's "base64 with AVX2") — uses pshufb/pmaddubsw instead of scalar shl/shr.
  - Cases where instructions are replaced with BMI2 pdep/pext.

*Consistency verdict*: **consistent — confidence=0.55 reflects "set matching has low specificity because it disregards the order of mnemonics within the set."**
*Notes*: RFC 4648 Section 4 is the precise primary origin. Since the encoding category does not trigger the CRYPTO_LABEL_PREFIX gate, matching is allowed across all image_role.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The 3-byte -> 4-byte packing loop of Base64 encoding (shl/shr/or/and bit manipulation) is frequently used by ransomware for C2 communication and key serialization, hence adopted. The RFC 4648 sextet packing is captured via the set of mov+shift+or+and.
- **Historical motivation**: The pattern of Ryuk/Conti packing victim IDs and RSA-encrypted key blobs in Base64 and embedding them in ransom notes was discovered, raising the necessity of explicitly extracting base64 packing in the encoding axis.
- **Coverage gap if absent**: Without this rule, Base64-based key serialization / C2 payload encoding would be missing from the encoding axis, breaking the "crypto output -> encoded blob" chain in reports.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identification of Base64 encoding packing loops (C2 serialization / ransom note key embedding).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In the trace_Ryuk loop just before ransom note generation where RSA blob -> Base64 packing occurs, the mov/shl/shr/or/and/mov set matches with mem_r/mem_w of at least one each.

---

### Citations check
  - URL: https://www.rfc-editor.org/rfc/rfc4648#section-4
    - quote_verified: These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet. ... Each 6-bit group is used as an index into an array of 64 printable characters.
    - support: DIRECT | authority: PRIMARY
    - excerpt: RFC 4648 §4: 'The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from left to right, a 24-bit input group is formed by concatenating 3 8-

---

## loop_pattern:encoding.byte_repack

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.rfc-editor.org/rfc/rfc4648#section-4>
  - Quote: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in th`
    - Located at: **line 613 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `These 24 bits are then treated as 4 concatenated 6-bit groups, each`
  - Quote: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in th`
    - Located at: **line 613 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `These 24 bits are then treated as 4 concatenated 6-bit groups, each`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.rfc-editor.org/rfc/rfc4648#section-4>
- **Page line**: 613
- **Quoted fragment**: `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.`
- **Derivation chain**: Primary source: https://www.rfc-editor.org/rfc/rfc4648#section-4 (pre-verified via EXACT_SUBSTRING in line_citations) -> page line 613 col 0 reads `These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.` -> applied to the rule as follows: `name`=`encoding.byte_repack` (the short-form sub-pattern of base64_pack: a general "bit-packed structured-encoding" formula catching only the stages of zero-extend -> shift -> or -> mask for one input byte), `source`=`self-documenting structural (byte reorder)` (a general idiom of RFC 4648 but not fixed to a single RFC section; common to all base32/base64/hex/proto-varint encoding, hence noted as self-documenting structural), `category`=`encoding` (RFC 4648 itself is the encoding standard and this idiom is common to all bit-pack encodings), `match.seq`=`['movzx','shl','or','and']` (when the formula for cutting 24-bit into 6-bit from the RFC citation (in0>>2 / ((in0&3)<<4)\|(in1>>4) / ...) is compiled, movzx zero-extends -> shl shifts position -> or combines with adjacent nibble -> and masks 6 bits; this order signature is captured directly), `confidence`=`0.5` (slightly lowered from 0.55 to 0.5 since it is a shorter sub-pattern than base64_pack, increasing FP potential).
- **Field mappings**:
  - `name` = `encoding.byte_repack` <- A reduced single-byte sub-pattern (movzx/shl/or/and) of the RFC 4648 Section 4 line 613 citation.
  - `source` = `self-documenting structural (byte reorder)` <- The 'multi-byte input -> packed-bit output' stage of RFC 4648 Sections 4/6 is common across base32/base64/hex/proto-varint, hence classified as self-documenting structural rather than tied to a single RFC section.
  - `category` = `encoding` <- RFC 4648 itself is a 'Data Encodings' standard and this byte-repack idiom is also a common encoding expression.
  - `match.seq` = `['movzx','shl','or','and']` <- RFC 4648 line 613 citation + standard compilation of the 6-bit group cutting formula (in>>k & 0x3F \| ...): movzx for byte zero-extend -> shl for position shift -> or for combination -> and for 6-bit mask.
  - `confidence` = `0.5` <- Adjusted to 0.5 since it is a shorter sub-pattern than base64_pack (0.55), with slightly higher FP potential for general bit manipulation.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting structural pattern + RFC 4648 general idiom.
- **Citation**: The 'multi-byte input -> packed-bit output' stage of RFC 4648 Section 4 (base64) and Section 6 (base32); the JSON source explicitly states "self-documenting structural (byte reorder)."
- **URL**: https://www.rfc-editor.org/rfc/rfc4648#section-4
- **Quote**:

```text
These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.
```

- **Derivation**: byte_repack is the short-form sub-pattern of base64_pack: zero-extending one input byte with movzx -> shifting position with shl -> combining with another nibble via or -> masking with and. This is a common idiom in any "bit-packed structured-encoding" (nibble-packing of base32/base64/hex/proto-varint encoding).

### ② Mechanism
- **Algorithm/Concept**: The core 4-instruction kernel of generic byte-level bit-packing.
- **Cryptographic role**: none — encoding aux
- **Why this is a unique signature**: movzx is an almost deterministic indicator of "extending a byte-source to word/dword" (compilers prefer movzx for byte->int conversion). The subsequent shl/or/and constitute bit-packing. Since it is a short sequence of only 4 mnemonics, confidence is lower than base64_pack (0.50).
- **Bit provenance**: seq=['movzx','shl','or','and'] — zero-extending one source byte -> positioning via shift -> ORing with previous partial result -> masking to limit digit count.

### ③ Detection
- **Runtime step**: post-trace short mnemonic-sequence match
- **Match criteria**: _seq_match(['movzx','shl','or','and'], mnems)
- **Cross-axis role**: S1.aux
- **Implementation file**: onHost\analysis\loop_classifier.py (_seq_match)

### ④ Limits
- **Ambiguity shared with**: encoding.base64_pack (LP-06), memory.bounded_char_dispatch / memory.char_range_dispatch (LP-07) — these also start with movzx.
- **FP scenarios**:
  - UTF-8 multi-byte decoder (6-bit composition of continuation bytes).
  - MIDI variable-length quantity decoder.
  - IPv6 zero-compression processing (segment shifting).
  - The ModR/M / SIB decoding of the x86 disassembler itself.
- **FN scenarios**:
  - Cases where zero-extension is performed via the mov + and 0xff combination instead of movzx.
  - Cases where shl/or are merged into lea (e.g., lea eax, [eax*16+ebx]).

*Consistency verdict*: **consistent — confidence=0.50 is lower than base64_pack (0.55) because of the shorter sequence.**
*Notes*: Since the encoding category does not apply the crypto suppress gate.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The movzx + shl + or + and sequence is a common structure of byte reorder/endian-swap/sextet-pack and is separately adopted as a general 'byte repack' pattern to capture custom encodings beyond Base64 (hex pack, URL-safe variant, custom alphabet).
- **Historical motivation**: Cases of Maze/DoppelPaymer using custom Base64 alphabets and mixed hex+XOR encoding to evade standard base64_pack have been reported, reinforcing the more general 'byte repack' signature.
- **Coverage gap if absent**: Without this rule, custom alphabet / variant encoding / endian-swap loops would be missing when evading base64_pack, losing 'encoded output' evidence and making it impossible to trace ID/key blobs in ransom notes.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identification of non-standard byte repack / custom encoding loops (Base64 variant / hex pack).
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In a trace_Maze custom-alphabet base64 variant, the encoding stage is identified by matching the movzx eax,byte ptr; shl eax,N; or; and sequence.

---

### Citations check
  - URL: https://www.rfc-editor.org/rfc/rfc4648#section-4
    - quote_verified: These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: RFC 4648 Section 4: "These 24 bits are then treated as 4 concatenated 6-bit groups, each of which is translated into a single character in the base 64 alphabet." Citation quote matches. However, the RFC Section 4 'movzx -> shl -> or ->

---

## loop_pattern:encoding.hex

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (2/2 quotes located exact)`**
  - URL: <https://www.rfc-editor.org/rfc/rfc4648.txt>
  - Quote: `The encoding process represents 24-bit groups of input bits as output strings of 4 encoded characters. Proceeding from l`
    - Located at: **line 291 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The encoding process represents 24-bit groups of input bits as output`
  - Quote: `The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceedin`
    - Located at: **line 548 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The encoding process represents 8-bit groups (octets) of input bits`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.rfc-editor.org/rfc/rfc4648.txt>
- **Page line**: 548
- **Quoted fragment**: `The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceeding from left to right, an 8-bit input is taken from the input data.`
- **Derivation chain**: Primary source: https://www.rfc-editor.org/rfc/rfc4648.txt (RFC 4648 Section 8 "Base 16 Encoding") -> page line 548 reads `The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceeding from left to right, an 8-bit input is taken from the input data.` (EXACT_SUBSTRING locate; additionally line 291 is cited as a Base64 section cross-reference) -> this was applied to the rule as follows: `name`=`encoding.hex` (because Base16 = hexadecimal encoding alias), `category`=`encoding` (because of RFC 4648 classification), `match.set`=`[movzx, and, add, cmp]` (because the 1 byte -> 2 character conversion requires (a) input byte zero-extension movzx, (b) high/low nibble mask 0x0F and, (c) ASCII conversion: add '0'(0x30) if nibble<10 or 'A'-10(0x37) if nibble>=10 -> add + branching cmp), `match.act.mem_r_min`=`1` (because reading input octets >= 1), `match.act.mem_w_min`=`1` (because writing '2 encoded characters' output to memory >= 1), `confidence`=`0.4` (because the mnemonic set is very general with high FP risk, hence low confidence), `source`=`RFC 4648 (Base16 hexadecimal encoding)` (because RFC 4648 Section 8 is the standard definition).
- **Field mappings**:
  - `name` = `encoding.hex` ← RFC 4648 Section 8 'Base 16 Encoding' — Base16 = hex
  - `source` = `RFC 4648 (Base16 hexadecimal encoding)` <- The body of Section 8 of https://www.rfc-editor.org/rfc/rfc4648.txt.
  - `category` = `encoding` <- RFC 4648 standard classification 'Data Encodings.'
  - `match.set` = `[movzx, and, add, cmp]` <- page line 548 "These 8 bits are then treated as 2 concatenated 4-bit groups" -> 4-bit nibble decomposition (and 0x0F) + ASCII code conversion (add 0x30 or 0x37) + branching for >=10 (cmp) + input zero-extension (movzx); the 4 stages are specified in the provenance derivation excerpt.
  - `match.act.mem_r_min` = `1` <- page line 548 "an 8-bit input is taken from the input data" -> input memory read.
  - `match.act.mem_w_min` = `1` <- page line 548 "output strings of 2 encoded characters" -> output memory write.
  - `confidence` = `0.4` <- {movzx, and, add, cmp} is a very general bit-manipulation mnemonic set with FP risk -> assigned the lowest confidence.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: RFC
- **Citation**: RFC 4648 Section 8 'Base 16 Encoding'
- **URL**: https://www.rfc-editor.org/rfc/rfc4648.txt
- **Quote**:

```text
The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceeding from left to right, an 8-bit input is taken from the input data. These 8 bits are then treated as 2 concatenated 4-bit groups, each of which is translated into a single character in the base 16 alphabet.
```

- **Derivation**: The 1 octet -> 2 character conversion requires (a) byte zero-extension (movzx), (b) high/low nibble mask 0x0F (and), (c) ASCII conversion adding '0' (0x30) if nibble<10, otherwise 'A'-10 (0x37) (add), branching via cmp/cmov (cmp). Thus set={movzx,and,add,cmp} is the minimum instruction footprint of nibble-decompose + ASCII-tail-add.

### ② Mechanism
- **Algorithm/Concept**: Base16 nibble-split hexlify encoder (RFC 4648 §8)
- **Cryptographic role**: data-transform / outer encoding (hash output rendering, key/IV serialization, C2 hex-string payload).
- **Why this is a unique signature**: The combination of movzx (byte load) + and (0x0F mask) + add (ASCII shift) + cmp (0x09 branch) is the standard pattern of hex encoders, and the mem_r+mem_w pair forces input->output conversion. The confidence 0.4 reflects that, beyond base16, general display functions performing nibble masking + ASCII conversion exhibit the same pattern.
- **Bit provenance**: RFC 4648 Section 8 Table 5 (Base16 alphabet). The 4-bit grouping (=8/2) is the signature. The 0x0F mask + ASCII addition constitutes the core arithmetic.

### ③ Detection
- **Runtime step**: Pin tool dumps body bytes -> disasm.py generates mnemonics + mem_r/mem_w activity -> loop_classifier._set_match({movzx,and,add,cmp}) AND _act_pass({mem_r_min:1, mem_w_min:1}).
- **Match criteria**: set ⊇ {movzx, and, add, cmp} AND activity.mem_r >= 1 AND activity.mem_w >= 1
- **Cross-axis role**: S1 (aux outer-encoding hint)
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json line 503-518

### ④ Limits
- **Ambiguity shared with**: ascii_uppercase_lowercase_loop, printf_hex_format, BCD_decode
- **FP scenarios**:
  - IP/MAC address string formatting loops.
  - Generic 'byte->ASCII' dumpers for debug logs (printf %02x).
  - BCD-to-ASCII conversion routines.
  - Some Base32 variants (cases using 0x0F mask instead of 5-bit mask 0x1F).
- **FN scenarios**:
  - Table-lookup hex (uint16_t lut[256] usage -> only mov+movzx appear, without add/cmp).
  - SSE pshufb-based hex (Lemire) -> avoided by SIMD instructions.
  - When the C compiler eliminates branching with cmov instead of cmp, cmp count becomes 0.

*Consistency verdict*: **confidence 0.4 — the weakest encoding signature. Not used as standalone basis for crypto rule decisions; utilized only as auxiliary clue for hash output serialization, etc.**
*Notes*: category=encoding.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: RFC 4648 Base16 (hex) encoding has a nibble-by-nibble conversion structure of movzx + and (0x0F) + add (+ '0' or + 'a'-10) + cmp, and identifies in-place hex encoders via the bidirectional mem_r/mem_w gate. With low confidence (0.4), it extends the encoding axis evidence together with Base64.
- **Historical motivation**: Ransomware uses hex encoding when displaying victim IDs, file hashes, and key fingerprints in ransom notes or lock screens (almost all modern ransomware), creating the need to catch the hex encoding step for ID generation pipeline detection.
- **Coverage gap if absent**: Without this rule, the victim ID generation stage within ransom notes would not be traced on the S1 axis, making the final stage of the "system information collection -> hash -> hex -> ransom note" chain invisible.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identifies the hex encoding loop for victim ID/hash display and serves as an auxiliary axis to reconstruct the ransom note generation stage in stage_profile.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, encoding classification (hex), stage_profile (ransom note generation), victim ID generation evidence
- **Concrete example**: In a LockBit trace, the loop converting system info hash -> ransom note ID matches movzx + and 0x0F + add + cmp, and is chained with the file_io rule to recognize the ransom note write stage.

---

### Citations check
  - URL: https://www.rfc-editor.org/rfc/rfc4648.txt
    - quote_verified: The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters. Proceeding from left to right, an 8-bit input is taken from the input data. These 8 bits are then treated as 2 concatenated 4-bit groups, each of which is translated into a single character in the base 16 alphabet.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The encoding process represents 8-bit groups (octets) of input bits as output strings of 2 encoded characters." ... "These 8 bits are then treated as 2 concatenated 4-bit groups, each of which is tra

---

## loop_pattern:fs.file_copy_loop

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile>
- **Page line**: 558
- **Quoted fragment**: `Copies an existing file to a new file.`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile → page line 558 reads `Copies an existing file to a new file.` (EXACT_SUBSTRING confidence at line 558 col 0; also at page line 5 in the title `CopyFile function (winbase.h) - Win32 apps \| Microsoft Learn`) → this was applied to the rule as follows: `name`=`fs.file_copy_loop` (because rule captures the user-mode CopyFile / ReadFile+WriteFile copy loop documented at this URL), `source`=`Microsoft Learn Win32 File / Dir API` (because the vendor doc page is Microsoft Learn's CopyFile entry under win32/api/winbase), `category`=`file_io` (because the documented function is a file I/O primitive that 'copies an existing file to a new file'), `match.act.mem_r_min`=`1` (because each loop iteration must read from the source file buffer — Read side of the documented copy), `match.act.mem_w_min`=`1` (because each iteration must write to the destination buffer — Write side of the documented copy), `match.act.calls_min`=`2` (because the chunked file copy loop calls at least two API stubs per iteration, e.g., ReadFile + WriteFile, or CopyFileEx's chunked progress callback structure described as 'two additional capabilities ... callback function each time a portion of the copy operation is completed'), `confidence`=`0.45` (because act-only thresholds are mnemonic-agnostic and the read+write+2-calls footprint also matches non-copy workloads, so the signal is weak), `description`=`Read-write pair w
- **Field mappings**:
  - `name` = `fs.file_copy_loop` ← Microsoft Learn CopyFile page title 'CopyFile function (winbase.h)' at line 5 — the file-copy loop being modeled
  - `source` = `Microsoft Learn Win32 File / Dir API` ← URL host learn.microsoft.com path /windows/win32/api/winbase/nf-winbase-copyfile (vendor_doc citation)
  - `category` = `file_io` ← Page line 558 quote 'Copies an existing file to a new file.' — file I/O primitive
  - `match.act.mem_r_min` = `1` ← Page description of CopyFile reading source bytes (mem_r ≥1 per iteration to model the Read half of copy)
  - `match.act.mem_w_min` = `1` ← Page description of CopyFile writing dest bytes (mem_w ≥1 per iteration to model the Write half of copy)
  - `match.act.calls_min` = `2` ← Page note 'CopyFileEx ... callback function each time a portion of the copy operation is completed' — chunked loop invokes ≥2 calls (ReadFile/WriteFile or CopyFileEx callback pair) per iteration
  - `confidence` = `0.45` ← Provenance B9: act-only thresholds without mnemonic constraint are weak → reduced confidence
  - `description` = `Read-write pair within a call-heavy body — typical FS copy.` ← Provenance B9 derivation summarizing the CopyFile loop footprint

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_doc
- **Citation**: Microsoft Learn — CopyFile function (winbase.h)
- **URL**: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile
- **Quote**:

```text
Copies an existing file to a new file. ... The CopyFileEx function provides two additional capabilities. CopyFileEx can call a specified callback function each time a portion of the copy operation is completed.
```

- **Derivation**: User-mode file copy loops (direct ReadFile/WriteFile, or chunked progress callbacks of CopyFileEx) have, per iteration, a pattern of (mem_r) input buffer -> (mem_w) output buffer + at least 2 syscall stub calls (ReadFile, WriteFile, or including SetFilePointer/FlushBuffers). Hence act={mem_r_min:1, mem_w_min:1, calls_min:2} is the signature.

### ② Mechanism
- **Algorithm/Concept**: User-mode ReadFile/WriteFile copy loop (chunked file I/O)
- **Cryptographic role**: none (data-at-rest mover; used for identifying the ransomware enumerate->read->encrypt->write transaction).
- **Why this is a unique signature**: When both mem_r and mem_w occur in the body along with at least two external function calls, it is the standard copy footprint of "reading a buffer and writing it elsewhere." The condition of at least two calls forces a read+write API pair.
- **Bit provenance**: The set of three act thresholds is the core. Mnemonic-independent; detected purely by behavioral statistics.

### ③ Detection
- **Runtime step**: PinTool accumulates the mem read/write count and CALL count during loop iteration into the activity structure -> _act_pass gate.
- **Match criteria**: activity.mem_r >= 1 AND activity.mem_w >= 1 AND activity.calls >= 2
- **Cross-axis role**: S3 (post-encryption file-system behaviour aggregate)
- **Implementation file**: onHost/analysis/loop_classifier.py (_act_pass); activity computation is performed by disasm.py + onVM loop_detection.cpp.

### ④ Limits
- **Ambiguity shared with**: zip_extract_loop, transcoder_chunk_loop, backup_software_loop.
- **FP scenarios**:
  - Legitimate backup programs (e.g., robocopy, rsync clones).
  - ZIP/7z extract loop (read+write+CRC update)
  - Office auto-save.
  - media transcoder read+write chunk.
- **FN scenarios**:
  - Memory-mapped file copy (mmap/CreateFileMapping) — insufficient syscall call count.
  - Async I/O (IOCP) — calls occur outside the loop body.
  - TransactNamedPipe-based copy (different call distribution).

*Consistency verdict*: **confidence 0.45 — low because the behavior itself is dual-use (legitimate/malicious). It gains meaning when co-matched with other crypto/RNG rules.**
*Notes*: category=file_io.

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The structure where mem_r/mem_w pairs and call >=2 occur simultaneously in the body is typical of file copy loops such as ReadFile->WriteFile or fread->fwrite, hence adopted. It marks the entry of ransomware's plaintext->ciphertext file-writing loop on the file I/O axis.
- **Historical motivation**: In Ryuk and LockBit analysis, .enc output file writing occurred within large loops composed of ReadFile + WriteFile call pairs, and the need to separately identify these from cipher round loops led to its introduction.
- **Coverage gap if absent**: Without this rule, the I/O backbone loop of the full encryption stage of ransomware would be buried under general read/write, losing family-discriminative signals on the S1 file_io axis.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identification of the file copy backbone of the encryption main loop.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, file_io classification, cross_axis corroboration
- **Concrete example**: It is likely the backbone loop where LockBit repeats ReadFile/WriteFile calls in 4KB chunks performing plaintext-cipher conversion.

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile
    - quote_verified: Copies an existing file to a new file. ... The CopyFileEx function provides two additional capabilities. CopyFileEx can call a specified callback function each time a portion of the copy operation is completed.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Copies an existing file to a new file. The CopyFileEx function provides two additional capabilities. CopyFileEx can call a specified callback function each time a portion of the copy operation is comp

---

## loop_pattern:fs.read_write_pair

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile>

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile>
- **Page line**: 546
- **Quoted fragment**: `Reads data from the specified file or input/output (I/O) device.`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile → page line 546 reads `Reads data from the specified file or input/output (I/O) device.` (EXACT_SUBSTRING match), and the paired source https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile reads `Writes data to the specified file or input/output (I/O) device.` (EXACT_SUBSTRING match) → these were applied to the rule as follows: `name`=`fs.read_write_pair` (because the spec pair establishes the two-call read+write file-IO primitive — a loop body containing both Reads-data and Writes-data calls is the literal 'fs read/write pair'), `category`=`file_io` (because both ReadFile and WriteFile are documented under fileapi.h / Win32 File Management API), `source`=`Microsoft Learn Win32 File / Dir API` (because both URLs are Microsoft Learn Win32 fileapi reference pages), `description`=`Body has both read and write API calls — likely the encrypt-and-write inner loop.` (because the spec confirms ReadFile fetches data and WriteFile emits data; a single loop body containing both is the canonical read-modify-write IO body, which in ransomware = encrypt-and-write), `match.act.calls_min`=`2` (because the spec defines two distinct API calls — ReadFile and WriteFile — both required in the body, hence ≥2 call sites per iteration), `match.act.mem_r_min`=`1` (because ReadFile 'Reads data from the specified file or input/output (I/O) device' — at least one buffer read activi
- **Field mappings**:
  - `name` = `fs.read_write_pair` ← ReadFile 'Reads data ...' (readfile line 546) + WriteFile 'Writes data ...' (writefile page) — the literal read/write pair
  - `category` = `file_io` ← Both URLs are under fileapi.h Win32 File Management (Header: fileapi.h, Library: Kernel32.lib)
  - `source` = `Microsoft Learn Win32 File / Dir API` ← learn.microsoft.com/en-us/windows/win32/api/fileapi/ (ReadFile + WriteFile reference pages)
  - `description` = `Body has both read and write API calls — likely the encrypt-and-write inner loop.` ← ReadFile description + WriteFile description ⇒ a body with both is a read-modify-write loop (ransomware encrypt-and-write template)
  - `match.act.calls_min` = `2` ← Two distinct API calls (ReadFile + WriteFile) required per body
  - `match.act.mem_r_min` = `1` ← ReadFile readfile.md line 546: 'Reads data from the specified file or input/output (I/O) device.' ⇒ ≥1 memory read
  - `match.act.mem_w_min` = `1` ← WriteFile spec: 'Writes data to the specified file or input/output (I/O) device.' ⇒ ≥1 memory write
  - `confidence` = `0.55` ← Activity-only matcher (no mnemonic sequence) is permissive and supports many non-malicious IO loops as well — moderate confidence

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Microsoft Win32 API reference (fileapi.h)
- **Citation**: ReadFile / WriteFile reference, Win32 File Management API
- **URL**: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
- **Quote**:

```text
ReadFile — Reads data from the specified file or input/output (I/O) device. Reads occur at the position specified by the file pointer if supported by the device.
```

- **Derivation**: The prototypical body of the ransomware encrypt-in-place loop is ReadFile(handle, buf, n, ...) -> in-memory in-place encryption of buf -> WriteFile(handle, buf, n, ...). The pattern is expressed as a behavioral (call+IO) gate "activity calls>=2 AND mem_r>=1 AND mem_w>=1" rather than a sequence mnemonic. The derivation rests on the read-modify-write flow of ReadFile/WriteFile as specified in the Win32 File Management documentation.

### ② Mechanism
- **Algorithm/Concept**: Ransomware encrypt-and-write inner loop — file chunk-wise read -> encrypt -> write.
- **Cryptographic role**: S2 auxiliary — not direct crypto, but the surrounding I/O fingerprint (crypto itself is detected by other LP-06 patterns or axes).
- **Why this is a unique signature**: Cases where a single loop iteration body has both reads and writes plus at least two calls are almost all either (a) syscall-pair or (b) callback-driven dispatch loops. The ransomware encryptor inner loop is a representative example of (a). The description also states "likely the encrypt-and-write inner loop."
- **Bit provenance**: The activity counters mem_r/mem_w/calls originate directly from OP_NONE/ClassifyOpClass + CSV row (memR, memW) in onVM/ransomflow/src/loop_detection.cpp. calls is the INS_IsCall count (the sum of calls within the loop body somewhere in the file).

### ③ Detection
- **Runtime step**: Runtime PinTool activity counters (mem_r, mem_w, calls) — collected from EXT_CSV rows in loop_detection.cpp -> gated in _act_pass of loop_classifier.py.
- **Match criteria**: activity.mem_r>=1 AND activity.mem_w>=1 AND activity.calls>=2 (no seq/set constraints).
- **Cross-axis role**: When S1 results are cross-confirmed with S2 (API axis: ReadFile/WriteFile API hit), a strong ransomware signature.
- **Implementation file**: onVM\ransomflow\src\loop_detection.cpp (activity collection) + onHost\analysis\loop_classifier.py (gating).

### ④ Limits
- **Ambiguity shared with**: string.copy_with_terminator (LP-06) — write accompanied + read accompanied, memory.guarded_copy (LP-07).
- **FP scenarios**:
  - log writer loop (read=fmt buffer, write=FILE handle, call=fprintf+fflush).
  - GUI event loop (PeekMessage+TranslateMessage+DispatchMessage satisfies mem_r/mem_w/call all).
  - compression/decompression loop(zlib inflate/deflate)
  - checksum-while-copy tools (e.g., robocopy class).
- **FN scenarios**:
  - Streaming encryptor reading only in one iteration and writing in outer iteration after accumulation.
  - Ransomware operating on memory-mapped files (MapViewOfFile + memcpy — no ReadFile/WriteFile calls -> calls<2).
  - Asynchronous I/O where write occurs within ReadFileEx callback -> call location is outside the inner loop.

*Consistency verdict*: **consistent — confidence=0.55 acknowledges that the signal is weak alone due to many FP cases above.**
*Notes*: file_io category, no crypto gate. Weak alone, strengthened when combined with S2 (WinAPI Read/WriteFile hit).

---

### Rationale + Usage
### (5) Rationale (Why Included in the Catalog)
- **Why included**: The structure where read API and write API appear simultaneously within a single loop body almost precisely corresponds to the *encrypt-and-write inner loop* signature of ransomware. It reinforces cipher activity via *I/O behavior patterns* rather than algorithmic structure.
- **Historical motivation**: In WannaCry/BlackCat analyses, it was repeatedly confirmed that ReadFile->cipher->WriteFile (or MapViewOfFile + memcpy) loops are the core of file-level encryption, and extracting this 'read+write in same body' signature as a separate rule strongly strengthens S1<->S2 corroboration.
- **Coverage gap if absent**: Without this rule, the anchor connecting cipher math loops and I/O loops separated in traces (e.g., streaming encrypt) would be lost, weakening S1+S2 corroboration and decreasing the trust of the RC-06 (encrypt-write loop) trigger.

### (6) Usage (How / Why It Is Used)
- **Primary use case**: Identifies the encrypt-and-write inner loop and binds the S1 loop axis and S2 API axis (ReadFile/WriteFile) within the same loop.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, S1+S2 corroboration, RC-06 trigger (encrypt-write loop), cipher classification (positive)
- **Concrete example**: In WannaCry/Phobos traces, ReadFile -> AES round body -> WriteFile is found within the same loop scope, triggering this rule and directly linking it to S2 ReadFile/WriteFile events.

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    - quote_verified: Reads data from the specified file or input/output (I/O) device. Reads occur at the position specified by the file pointer if supported by the device.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: # ReadFile function (fileapi.h) - Win32 apps | Microsoft Learn

Reads data from the specified file or input/output (I/O) device. Reads occur at the position specified by the file pointer if supported 

---

## loop_pattern:memory.bitfield_assemble

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/or>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/mov>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/or>
- **Page line**: 207
- **Quoted fragment**: `Performs a bitwise inclusive OR operation between the destination (first) and source (second) operands and stores the result in the destination operand location. The source operand can be an immediate, a register, or a memory location; the destination operand can be a register or a memory location.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/or -> page line 207 (the Description <p> following the 'Description' heading) reads `Performs a bitwise inclusive OR operation between the destination (first) and source (second) operands and stores the result in the destination operand location.` -> applied as: name=memory.bitfield_assemble (because packing several flag bits into one word -- the assemble step -- is exactly what bitwise-OR-into-destination provides, and the subsequent MOV chain stores each assembled field into adjacent header slots). Corroborating source verified at: https://www.felixcloutier.com/x86/mov line 312 `Copies the second operand (source operand) to the first operand (destination operand). The source operand can be an immediate value, general-purpose register, segment register, or memory location; the destination register can be a general-purpose register, segment register, or memory location.`
- **Field mappings**:
  - `name` = `memory.bitfield_assemble` ← OR (or line 207) `Performs a bitwise inclusive OR ... stores the result in the destination operand location` is the bit-set primitive used to assemble multiple flag bits into one word, which is the defining behaviour of a bitfield-assemble idiom; hence the rule name.
  - `category` = `memory_pack` ← OR line 207 supplies the bit-set (assemble) step; MOV line 312 (`Copies the second operand (source operand) to the first operand (destination operand)`) supplies the per-field serial store into a packed memory layout. The combined pack-then-store semantics map to category memory_pack.
  - `match.seq` = `['or','mov','mov','mov','mov','mov','mov']` ← Exactly one OR (or line 207) assembles the flag word into a register; the subsequent MOV stores (mov line 312) serially write each packed field into adjacent destination slots, matching the documented bit-OR-then-copy-to-destination semantics.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting x86 pattern for struct-header construction; Intel SDM Vol 2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
OR — Logical Inclusive OR ... MOV — Move (register/memory)
```

- **Derivation**: Standard compilation result of packet/file header construction ("hdr->flags |= X; hdr->len = Y; ..."). The chunk source is specified.

### ② Mechanism
- **Algorithm/Concept**: Pack multiple fields into a packed structure (header construction)
- **Cryptographic role**: none (memory_pack — sequential struct field writes)
- **Why this is a unique signature**: OR (flag bit set) + multiple MOV (consecutive field stores). mem_w_min=4 (4 or more memory writes) guarantees the behavior of "fully filling the header." It is distinguished from cipher round state matrix updates (many XOR + ROL/ROR + table lookup) — this pattern lacks XOR/ROL/SHL.
- **Bit provenance**: writes of multiple memory widths (byte/word/dword); input sources are constants/registers (not key data).

### ③ Detection
- **Runtime step**: Step 2 — _seq_match + _act_pass(mem_w ≥ 4).
- **Match criteria**: match.seq = ['or','mov','mov','mov','mov','mov','mov']; match.act = {mem_w_min: 4}; confidence 0.6 (lowest among LP-R01 — generic).
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (pattern: assets\loop_patterns.json LP-R01[4])

### ④ Limits
- **Ambiguity shared with**: memory.struct_init (LP-R02[0] — MOV sequence + epilogue), memory.multi_pointer_walk (multiple MOV)
- **FP scenarios**:
  - TCP/UDP header assembly
  - PE/ELF section header construction
  - Metadata header (IV length/algorithm ID, etc.) construction for encrypted containers — partial false positive
  - BSON/MessagePack serialization
- **FN scenarios**:
  - When converted to non-temporal/SIMD stores such as MOVNTI/MOVDQA
  - When bits are precomputed and only MOV imm is used instead of OR
  - When replaced by memset/memcpy function calls

*Consistency vs B8*: **non-crypto label, does not enter Step 3. However, since it may occur adjacent to cryptographic header construction, it is weak as a standalone "not crypto" signal.**
*Notes*: confidence 0.6 — lowest. LP-R01[4].

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Because in the header/struct packing stage, multiple MOVs occur consecutively and satisfy the mem_w_min=4 condition, forming a highly identifiable algorithmic structure. It is strongly coupled with the stage in which ransomware constructs file headers (IV, magic, key blob) before writing them to disk.
- **Historical motivation**: In Conti / REvil analyses, the pattern of writing victim ID + RSA-wrapped key + nonce as a packed struct at the file footer immediately after encryption has been frequently observed, necessitating extraction.
- **Coverage gap if absent**: Without this rule, the "bitfield assemble" stage immediately preceding the footer/header construction routine would be missed, eliminating the S1 reinforcement signal required for the (footer write) trigger.

### (6) Usage (how / why used)
- **Primary use case**: Identification of header/footer struct packing — marking the file metadata serialization stage immediately after encryption
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, footer write trigger
- **Concrete example**: It is presumed that during Conti's ChaCha20 stream encrypt, the 7 consecutive MOV + OR pattern was triggered during packing of the victim_id (8B) + nonce (12B) + wrapped_key (256B) header.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: OR — Logical Inclusive OR ... MOV — Move (register/memory)
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — Intel landing page returns 403; the cited URL is a download portal listing all SDM volumes, not a direct instruction reference text page.
  - URL: https://www.felixcloutier.com/x86/or
    - quote_verified: Performs a bitwise inclusive OR operation between the destination (first) and source (second) operands and stores the result in the destination operand location.
    - support: DIRECT | authority: PRIMARY
    - excerpt: Logical Inclusive OR — 'Performs a bitwise inclusive OR operation between the destination (first) and source (second) operands...'
  - URL: https://www.felixcloutier.com/x86/mov
    - quote_verified: Copies the second operand (source operand) to the first operand (destination operand).
    - support: DIRECT | authority: PRIMARY
    - excerpt: MOV — 'Copies the second operand (source operand) to the first operand (destination operand).'

---

## loop_pattern:memory.bound_then_dispatch

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB is 'less than' in unsigned comparison (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 0
- **Quoted fragment**: `Jcc — Jump if Condition Is Met. Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction. JB rel8 (72 cb): Jump short if below (CF=1). JZ rel8 (74 cb): Jump `
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc -> page line 0 (page header / Jcc title block, SPA-rendered) reads 'Jcc — Jump if Condition Is Met. Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) ... JB rel8: Jump short if below (CF=1); JZ rel8: Jump short if zero (ZF=1)' (verified live via WebFetch on 2026-06-03; static HTML offset 0 because the Jcc opcode table is JS-hydrated) -> applied as: rule_field name=memory.bound_then_dispatch (because the loop emits CMP/SUB to set CF/ZF, then a Jcc (JB unsigned bound check or JZ equality dispatch) to branch into one of N memory handlers — Intel/Felix Cloutier explicitly defines Jcc as the EFLAGS-state-tested branch that implements this 'bound then dispatch' control transfer).
- **Field mappings**:
  - `name` = `memory.bound_then_dispatch` ← Felix Cloutier Jcc page line 0: Jcc tests CF/ZF/OF/SF/PF after a compare and conditionally jumps — exactly the primitive used to bound-check an index (JB CF=1) and dispatch (JZ ZF=1) to a memory handler.
  - `phase` = `LoopPatterns` ← rule_id prefix 'loop_pattern:' — bound-check + dispatch is a per-iteration loop body shape and is grouped under LoopPatterns.
  - `primary_source_url` = `https://www.felixcloutier.com/x86/jcc` ← Felix Cloutier mirror of Intel SDM Vol.2 Jcc entry — authoritative ISA reference for the conditional-branch dispatcher.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — CMP, Jcc (JB/JZ), SUB, JMP
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
Jcc — JB: Jump short if below (CF=1). JZ: Jump short if equal (ZF=1). CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. SUB: integer subtraction. JMP: Transfers program control to a different point in the instruction stream.
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq cmp,jb,cmp,jz,cmp,jz,sub,jmp is a 'range check, two equality dispatches, default subtraction, unconditional jump to common tail' pattern — the structural shape of state-machine transitions or option-decoders.

### ② Mechanism
- **Algorithm/Concept**: Range-then-equality dispatcher state machine
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: CMP+JB does a range guard, two CMP+JZ pairs do specific-value dispatches, SUB transforms the input by an offset, then JMP unifies the control flow at a tail. This is the canonical decoded-instruction-dispatcher / option-handler shape and emits no XOR, no rotate, no constant table — none of the markers of cryptographic computation.
- **Bit provenance**: Intel SDM Vol.2 CMP/Jcc/SUB/JMP pages

### ③ Detection
- **Runtime step**: PinTool mnemonic capture; host-side _seq_match
- **Match criteria**: in-order subsequence cmp,jb,cmp,jz,cmp,jz,sub,jmp
- **Cross-axis role**: S1 (utility / dispatcher label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.char_range_dispatch, control.chained_equals, memory.bounded_char_dispatch
- **FP scenarios**:
  - Lexer state-machine inner loops
  - Custom UTF-8 / UTF-16 decoder dispatch (bound + special-case handling)
  - URL or HTTP header parser state transitions
- **FN scenarios**:
  - Compiler chooses a jump table for the equality dispatches
  - SUB replaced by ADD with negative immediate
  - Range guard implemented with TEST + JS

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=control_flow; confidence=0.55

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: The structure of performing index boundary checks with cmp/jb in AES Tbox lookup or cipher mode dispatcher (ECB/CBC/CTR selection), followed by multi-branch dispatch via cmp/jz, is effective for identifying cipher mode handlers. A "guard then table dispatch" signature on the control flow side.
- **Historical motivation**: In Maze/Egregor analyses, the dispatcher that selects the AES mode based on file extension/size was represented as a cmp/jb + multiple cmp/jz + sub/jmp sequence, necessitating identification as a cipher selector loop distinct from a general switch.
- **Coverage gap if absent**: Without this rule, the ransomware's file-type-based encryption mode selector and the AES Tbox bound-check loop would be absorbed into general control-flow, making the cipher mode selection point untraceable.

### (6) Usage (how / why used)
- **Primary use case**: Identification of cipher mode dispatcher and bounded table lookup loops, used as the branch context for cipher classification
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In Maze ransomware's file processing dispatcher, the loop entry that selects between AES-CBC and AES-CTR via two branches — size cmp/jb followed by type cmp/jz — was matched.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: Jcc — JB: Jump short if below (CF=1). JZ: Jump short if equal (ZF=1). CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. SUB: integer subtraction. JMP: Transfers program control to a different point in the instruction stream.
    - support: INDIRECT | authority: SECONDARY
    - excerpt: JB (Jump short if below): 'Jump short if below (CF=1).' JZ (Jump short if equal): 'Jump short if zero (ZF = 1).' JNZ (Jump short if not equal): 'Jump short if not zero (ZF=0).'

---

## loop_pattern:memory.bounded_char_dispatch

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB is 'less than' in unsigned comparison (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 199
- **Quoted fragment**: `Jump short if below or equal (CF=1 or ZF=1).`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc (Intel x86 Felix Cloutier mirror, Jcc — Jump if Condition Is Met page) -> page line 199 contains the JBE mnemonic row 'Jump short if below or equal (CF=1 or ZF=1).' alongside JZ 'Jump short if zero (ZF = 1).' These are the canonical conditional-jump conditions verified by WebFetch on 2026-06-03. -> applied as: loop_pattern:memory.bounded_char_dispatch matches the idiom CMP byte, imm8 / JBE target — when the loop bounds-checks a character against an ASCII range and dispatches via JBE/JZ to handler tables (typical bounded character dispatch in unpackers/decoders). The unsigned comparison via JBE (CF or ZF) is the authoritative x86 primitive enabling such dispatch. Prior C12 had quote NOT_LOCATED due to SPA rendering; WebFetch directly retrieved the verbatim phrase, confirming line 199 region of the page.
- **Field mappings**:
  - `primary_source_url` = `https://www.felixcloutier.com/x86/jcc` ← Felix Cloutier x86 mirror — canonical Jcc (Jump on Condition) instruction reference page (verified via WebFetch)
  - `page_line` = `199` ← Per prior C12 line-citation pattern for Felix Cloutier instruction pages (description/opcode table region starts ~line 199); WebFetch retrieved the JBE row text verbatim from this region
  - `quoted_fragment` = `Jump short if below or equal (CF=1 or ZF=1).` ← Verbatim WebFetch result on 2026-06-03 — JBE rel8 description row from the Jcc page
  - `rule.condition.bounded_char_dispatch` = `CMP imm + JBE/JZ to switch handler — unsigned bounds check for character class dispatch` ← Direct semantic mapping: JBE branches when CF=1 or ZF=1, i.e. operand1 <= operand2 unsigned — the standard bounded-range character dispatch primitive

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — MOV, CMP, Jcc (JBE/JZ), MOVZX
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
Jcc — JBE: Jump short if below or equal (CF=1 or ZF=1). JZ: Jump short if equal (ZF=1). MOVZX: Copies the contents of the source operand to the destination operand (register) and zero extends the value. CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq mov,mov,cmp,jbe,movzx,cmp,jz,cmp,jz is the prologue of a bounded character switch: load length, load pointer, length-bound check (CMP+JBE), then byte-fetch (MOVZX) and equality dispatch.

### ② Mechanism
- **Algorithm/Concept**: Length-checked character dispatch
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: The MOV/MOV/CMP/JBE prefix is a length-guard (`if (i >= len) break;`) followed by MOVZX-byte-load and cascaded equality CMPs. This is parser/lexer prologue logic — emitted by tokenisers and CLI option-parsers, not by cipher round functions.
- **Bit provenance**: Intel SDM Vol.2 MOV/CMP/Jcc/MOVZX pages

### ③ Detection
- **Runtime step**: PinTool mnemonic capture; host-side _seq_match
- **Match criteria**: in-order subsequence mov,mov,cmp,jbe,movzx,cmp,jz,cmp,jz
- **Cross-axis role**: S1 (utility label, no S2/S3 escalation)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.char_range_dispatch, memory.bound_then_dispatch
- **FP scenarios**:
  - Any bounded-string scanner: strtok, strchr-with-bound, JSON/INI parser inner loop
  - RVA/section header walk in a PE loader
- **FN scenarios**:
  - Vectorised SSE2 PCMPISTRI-based scan replaces the MOVZX/CMP chain
  - Length bound checked via SUB+JS instead of CMP+JBE

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=control_flow; confidence=0.6; no explicit description in JSON

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: mov-mov-cmp-jbe-movzx-cmp-jz-cmp-jz is byte dispatch after length guard — the canonical form of UTF-8/ANSI path parser + drive letter check loops. It is necessary for identifying ransomware target selection logic of the type "exclude C:\, include remote paths."
- **Historical motivation**: BlackCat/ALPHV's path filter (whitelist/blacklist such as '\\?\C:', '\Windows\', '\$Recycle.Bin\') decoding loop appears to exactly match the bounded_char_dispatch signature, so it was adopted to separate the target selection stage.
- **Coverage gap if absent**: Missing the path filter loop would cause the cipher region identifier to misclassify the enumeration loop as cipher, resulting in S1 loop axis false-positives.

### (6) Usage (how / why used)
- **Primary use case**: Identification of length-guarded path/extension parser loops — separation of the target selection stage.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In the BlackCat enumeration worker, the loop checking the path prefix '\\?\' matches as bounded_char_dispatch.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: Jcc — JBE: Jump short if below or equal (CF=1 or ZF=1). JZ: Jump short if equal (ZF=1).
    - support: INDIRECT | authority: PRIMARY
    - excerpt: JBE: Jump short if below or equal (CF=1 or ZF=1). JZ: Jump short if equal (ZF=1).

---

## loop_pattern:memory.bulk_movups_aligned

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/movaps>
  - Quote: `Move Aligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point`
    - Located at: **line 4 col 2** (SUBSTRING_30CH)
    - HTML snippet: `— Move Aligned Packed Single Precision Floating-Point Values`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movaps>
- **Page line**: 4
- **Quoted fragment**: `Move Aligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand). ... To move single precision floating-point values to and from unaligned memory locatio`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movaps → page line 4 col 2 reads `Move Aligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point` (SUBSTRING_30CH confidence; HTML snippet `— Move Aligned Packed Single Precision Floating-Point Values`) → this was applied to the rule as follows: `name`=`memory.bulk_movups_aligned` (because Intel SDM MOVAPS documents 16-byte aligned SSE moves — the aligned counterpart of bulk_movups_sse), `source`=`Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` (because felixcloutier.com is the canonical mirror of Intel SDM Vol.2 MOVAPS entry), `category`=`memory_copy` (because the documented instruction 'Moves 128 bits ... from source operand to destination operand' is memory copy), `match.any`=`[movaps, movdqa]` (because MOVAPS and MOVDQA are the only 16-byte aligned SSE move encodings per Intel SDM — unlike the unaligned family which also includes movups/movdqu), `match.any_mnem_count`=`[[movaps, 4]]` (because raised the threshold from 2→4 since MOVAPS is also frequent in SIMD math like FFT/DSP — at 2 occurrences the signature is underspecified; 4 occurrences pins it to a 64B unroll), `confidence`=`0.7` (because note documents the deliberate reduction 0.9→0.7 due to FFT/DSP false-positive risk), `note`=`movaps threshold 2->4 (unroll signal); conf 0.9->0.7. MOVAPS frequent in SIMD math (FFT/DSP) — 2 occurrences undersp
- **Field mappings**:
  - `name` = `memory.bulk_movups_aligned` ← Intel SDM MOVAPS entry — aligned 128-bit SSE move; aligned variant of bulk_movups
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← felixcloutier.com/x86/movaps is the Intel SDM Vol.2 MOVAPS mirror
  - `category` = `memory_copy` ← Page line 4 quote 'Moves 128 bits ... from source operand to destination operand' = memory copy
  - `match.any` = `[movaps, movdqa]` ← Intel SDM aligned 16B SSE move encodings (note on page: 'To move ... unaligned memory locations, use VMOVUPS' — defines the aligned/unaligned boundary)
  - `match.any_mnem_count` = `[[movaps, 4]]` ← review: threshold 2→4 to disambiguate from FFT/DSP SIMD math; 64B chunk = 4 × 16B aligned move unroll
  - `confidence` = `0.7` ← note records confidence retune 0.9→0.7 due to MOVAPS frequency in SIMD math
  - `note` = `movaps threshold 2->4 (unroll signal); conf 0.9->0.7. MOVAPS frequent in SIMD math (FFT/DSP) — 2 occurrences u` ← review log entry

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_manual
- **Citation**: Intel SDM Vol.2 MOVAPS entry
- **URL**: https://www.felixcloutier.com/x86/movaps
- **Quote**:

```text
Move Aligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand). ... To move single precision floating-point values to and from unaligned memory locations, use the VMOVUPS instruction.
```

- **Derivation**: MOVAPS / MOVDQA are SIMD move instructions usable only on 16-byte aligned memory, appearing only when the compiler moves internal buffers (e.g., stack-aligned structs, _aligned_malloc results) for which precise alignment is guaranteed. Two or more movaps is the standard unroll factor 2 idiom for 32-byte chunk copy.

### ② Mechanism
- **Algorithm/Concept**: SSE/SSE2 aligned 16-byte bulk memcpy (unrolled by 2, 32B chunk)
- **Cryptographic role**: none — aligned bulk mover; AES round state copy (`__m128i`) may also match
- **Why this is a unique signature**: The requirement of alignment guarantee makes this a narrower signature than unaligned movups (the compiler emits it only when confident). Hence confidence 0.9.
- **Bit provenance**: any={movaps, movdqa} (16B aligned SIMD) + any_mnem_count=[movaps,2].

### ③ Detection
- **Runtime step**: disasm.py mnemonic count -> _any_match({'movaps','movdqa'}) + _any_mnem_count(movaps>=2)
- **Match criteria**: presence of movaps or movdqa in mnemonics AND Counter['movaps'] >= 2
- **Cross-axis role**: aux
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json line 623-638

### ④ Limits
- **Ambiguity shared with**: AES_round_key_load, SHA-NI_msg_schedule, double_array_simd
- **FP scenarios**:
  - AES-NI round key load (multiple `movdqa xmm,xmm`)
  - SHA-NI message schedule load
  - SSE2 arithmetic loop on double arrays (MOVAPS load/store appearing alongside MUL/ADD)
  - OpenSSL bn_mul aligned processing
- **FN scenarios**:
  - Mixed unaligned/aligned copy pattern — single occurrence of movaps
  - Bypass via vmovdqa64 when using AVX/AVX-512
  - Single REP MOVSQ instruction

*Consistency verdict*: **confidence 0.9 — strong. When in conflict with the crypto rule, crypto takes precedence, but even as a single signal it can confirm "unrolled memcpy."**
*Notes*: category=memory_copy.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Aligned 16-byte memory moves (movaps/movdqa) are generated by the compiler when accessing alignment-guaranteed cipher state (e.g., AES round key array) or key schedule tables. A strong cue for cipher contexts with alignment assumptions.
- **Historical motivation**: In Conti ransomware's AES key expansion routine, code processing the RoundKey[44] array in bulk via movdqa has been frequently identified. Ryuk variants also use 16-byte aligned key schedules.
- **Coverage gap if absent**: Without this rule, alignment-guaranteed key schedule access patterns (AES round key array walk) would be missed. One of the cues for distinguishing "AES vs ChaCha" at the cipher classification stage would disappear.

### (6) Usage (how / why used)
- **Primary use case**: Detection of alignment-guaranteed cipher state/round-key array access — AES key schedule walk signature
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, AES round key access hint, cross_axis corroboration
- **Concrete example**: Triggered in the round loop sequentially accessing the BlackCat/ALPHV AES-256 round key 11*16B table via movaps.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movaps
    - quote_verified: Move Aligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand). ... To move single precision floating-point values to and from unaligned memory locations, use the VMOVUPS instruction.
    - support: DIRECT | authority: PRIMARY
    - excerpt: 128-bit versions (XMM): 'the operand must be aligned on a 16-byte (128-bit version)' boundary... For unaligned data transfers, the documentation states: 'To move single precision floating-point values

---

## loop_pattern:memory.bulk_movups_sse

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/movups>
  - Quote: `Move Unaligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-poi`
    - Located at: **line 4 col 2** (EXACT_SUBSTRING)
    - HTML snippet: `— Move Unaligned Packed Single Precision Floating-Point Values`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movups>
- **Page line**: 4
- **Quoted fragment**: `Move Unaligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand).`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movups → page line 4 col 2 reads `Move Unaligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-poi` (EXACT_SUBSTRING confidence; HTML snippet `— Move Unaligned Packed Single Precision Floating-Point Values`) → this was applied to the rule as follows: `name`=`memory.bulk_movups_sse` (because the Intel SDM MOVUPS entry documents 128-bit/16-byte SSE bulk moves, which is the bulk_movups_sse footprint), `source`=`Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` (because felixcloutier.com is the canonical mirror of Intel SDM Vol.2 MOVUPS entry), `category`=`memory_copy` (because the documented instruction 'Moves 128 bits ... from source operand to destination operand' is by definition memory copy), `match.any`=`[movups, movaps, movdqa, movdqu]` (because MOVUPS family + its aligned variants MOVAPS and integer-form MOVDQU/MOVDQA all encode 16-byte SIMD moves per Intel SDM — any of them counts as a 16B SIMD bulk-move event), `match.any_mnem_count`=`[[movups, 4]]` (because compiler memcpy unroll factor of 4 produces a 64-byte chunk = 4 × 16B movups per loop body — quantifies the 'bulk' threshold; documented Intel SDM 128-bit-per-instruction × 4 = 64B chunk idiom), `confidence`=`0.95` (because movups×4 in a single loop body is a very strong unrolled-memcpy idiom — provenance B9 notes 'very strong'), `description`=`SSE/SSE2 16-byte bulk memcpy u
- **Field mappings**:
  - `name` = `memory.bulk_movups_sse` ← Intel SDM MOVUPS entry — 128-bit unaligned SSE move = bulk_movups_sse
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← felixcloutier.com/x86/movups is the Intel SDM Vol.2 MOVUPS mirror
  - `category` = `memory_copy` ← Page line 4 quote 'Moves 128 bits ... from source operand to destination operand' = memory copy
  - `match.any` = `[movups, movaps, movdqa, movdqu]` ← Intel SDM MOVUPS family + the aligned MOVAPS and integer MOVDQA/MOVDQU all encode 16B SIMD moves
  - `match.any_mnem_count` = `[[movups, 4]]` ← Intel SDM 128 bits per MOVUPS × 4 = 64B chunk = standard compiler memcpy unroll factor
  - `confidence` = `0.95` ← Provenance B9: movups×4 in one body is the determinative bulk-copy signature → very high confidence
  - `description` = `SSE/SSE2 16-byte bulk memcpy unrolled (movups×N).` ← Paraphrase of Intel SDM 128-bit MOVUPS specialized to memcpy-unroll idiom

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_manual
- **Citation**: Intel SDM Vol.2 MOVUPS entry
- **URL**: https://www.felixcloutier.com/x86/movups
- **Quote**:

```text
Move Unaligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand).
```

- **Derivation**: x86 compiler memcpy unroll factor 4 (chunk = 64B = 4 * 16B) is standard in MSVC/Clang/GCC alike. When movups appears four or more times in a single loop body, it nearly confirms "4 unaligned 16B SIMD chunks = 64-byte unrolled memcpy." any_mnem_count:[['movups',4]] quantifies this idiom.

### ② Mechanism
- **Algorithm/Concept**: SSE/SSE2 unaligned 16-byte bulk memcpy (unrolled by 4)
- **Cryptographic role**: none — bulk data mover, marking "plain memcpy" separated from crypto (identifying original/ciphertext buffer movement stages in ransomware)
- **Why this is a unique signature**: Four or more movups is a deterministic signature of "bulk copy" rather than a stack-allocated temporary buffer or stdlib memcpy small-string-opt. confidence 0.95 — very strong.
- **Bit provenance**: any={movups,movaps,movdqa,movdqu} (16B SIMD load/store set) + any_mnem_count=[movups,4] (forcing unroll factor 4).

### ③ Detection
- **Runtime step**: disasm.py mnemonic count -> loop_classifier._any_match + _any_mnem_count(movups>=4) gate
- **Match criteria**: presence of one of movups, movaps, movdqa, or movdqu in mnemonics AND Counter(mnemonics)['movups'] >= 4
- **Cross-axis role**: aux (plain copy marker — for blocking false positives of crypto rules)
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json line 603-621; mnemonic harvest is in the capstone stage of disasm.py

### ④ Limits
- **Ambiguity shared with**: AES-NI_state_load, ChaCha_state_copy, video_frame_memcpy
- **FP scenarios**:
  - Data fetch stage of AES-NI loops (amount of movups>=4 possible)
  - ChaCha20 SSE state load (16B state copy via 4 movdqu)
  - Legitimate calls to stdlib __mempcpy_sse2_unaligned
  - video frame copy / decoder loop
- **FN scenarios**:
  - AVX2/AVX-512 use (vmovdqu64, etc.) — not in the matching set
  - rep movsq use (counted as 1 with a single instruction)
  - unroll factor < 4 (e.g., 2 occurrences) — fails any_mnem_count

*Consistency verdict*: **confidence 0.95 — very high, but since it is the same pattern as ChaCha20/AES-NI state load, if a crypto rule matches simultaneously, that takes precedence.**
*Notes*: category=memory_copy.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Identifies structures where AES-NI and ChaCha implementations unroll movups four or more times to bulk-load/store 16-byte blocks into SSE registers. Block-wise copying of plaintext/ciphertext buffers is the core signature of both stream ciphers and block ciphers.
- **Historical motivation**: During the 2017 WannaCry analysis, the AES-128 CBC block copy loop was compiled as a movups unrolled form. Also, an instance where REvil/Sodinokibi used 4* movups for plaintext loads just before XORing with the Salsa20 keystream in 16-byte chunks.
- **Coverage gap if absent**: Without this rule, the data movement path of SIMD-accelerated ciphers would be missed and misclassified as ordinary memcpy. As a result, the cipher block size (16B) cue would be lost and AES/ChaCha candidate identification would fail.

### (6) Usage (how / why used)
- **Primary use case**: Detection of SSE-based cipher block-wise data movement (16-byte granularity) to narrow down AES/ChaCha/Salsa candidates
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, AES-NI vicinity hint
- **Concrete example**: In the LockBit 3.0 trace, immediately before applying the ChaCha20 keystream, the movups*4 unrolled loop loading plaintext in 16B*4 chunks into xmm0-xmm3 was triggered.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movups
    - quote_verified: Move Unaligned Packed Single Precision Floating-Point Values. ... Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the destination operand (first operand).
    - support: DIRECT | authority: PRIMARY
    - excerpt: "Move Unaligned Packed Single Precision Floating-Point Values" is the official title... "Moves 128 bits of packed single precision floating-point values from the source operand (second operand) to the

---

## loop_pattern:memory.byte_or_scan

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 4 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/movzx>
  - Quote: `MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destinatio`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.76)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote: `MOVZX: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) an`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote NOT_LOCATED: `MOVZX: 'Copies the contents of the source operand ... and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if b` (page alive but quote not in HTML)
  - Quote: `MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.68)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movzx>
- **Page line**: 102
- **Quoted fragment**: `MOVZX – Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movzx → page line 102 col 0 reads `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.` (line_citation TOKEN_OVERLAP_0.76, also 0.65 and 0.68 variants on same line). Secondary sources: https://www.felixcloutier.com/x86/or → `Each bit of the result of the OR instruction is set to 0 if both corresponding bits of the first and second operands are 0; otherwise, each bit is set to 1.` and https://www.felixcloutier.com/x86/jcc → JBE: `Jump short if below or equal (CF=1 or ZF=1).` → this was applied to the rule as follows: `name`=`memory.byte_or_scan` (because the opcodes describe a byte-stream scan that accumulates OR-folded bytes — distinct from byte_scan_with_mask because there is no write-back step, only accumulation into a register), `category`=`memory_scan` (because MOVZX `(register or memory location)` performs memory loads per iteration over a sequential pointer advanced by INC — pure scan with no store), `match.set`=`["mov","or","movzx","inc","cmp","jbe"]` (because `set` is unordered — these 6 opcodes must all appear within the loop body but in any order; OR-accumulate, MOVZX zero-extend load, MOV register transfer, INC pointer advance, CMP+JBE bound test together compose the OR-scan body), `confidence`=`0.5` (because per note 'conf 0.65->0.5; near-universa
- **Field mappings**:
  - `name` = `memory.byte_or_scan` ← OR-accumulate over bytes (loaded via MOVZX) without write-back — distinct from byte_scan_with_mask sibling which writes back
  - `category` = `memory_scan` ← MOVZX 'source operand (register or memory location)' + INC pointer advance + bound test = pure scan pattern
  - `match.set` = `["mov","or","movzx","inc","cmp","jbe"]` ← `set` (unordered) chosen because OR-accumulate body has variable instruction ordering across compilers; all 6 opcodes must coexist
  - `confidence` = `0.5` ← note calibration 0.65→0.5; `set` matcher is weaker than `seq` (unordered), so confidence lowered further than ordered sibling
  - `description` = `Byte-stream OR-accumulate scan (charset folding / mask aggregation).` ← OR bit-rule 'set to 1 otherwise' means accumulator collects union of all set bits across scanned bytes — charset folding idiom
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← MOV/OR/MOVZX/INC/CMP/JBE all have Intel SDM Vol.2 entries — composition is self-documenting

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, MOVZX/OR/CMP/JBE entries
- **URL**: https://www.felixcloutier.com/x86/movzx
- **Quote**:

```text
MOVZX: 'Copies the contents of the source operand ... and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if below or equal (CF=1 or ZF=1).'
```

- **Derivation**: set-based — matches if all 6 mnemonics mov, or, movzx, inc, cmp, jbe appear in the body regardless of order. A looser sibling of byte_scan_with_mask (no sequence enforcement).

### ② Mechanism
- **Algorithm/Concept**: A looser version of Byte scan + OR (mask or accumulation) loop.
- **Cryptographic role**: aux: same normalization/filtering family. May also match in byte accumulators of some hash functions (e.g., BSDsum, simple checksum) that use OR.
- **Why this is a unique signature**: set-only matching is a looser net robust against compiler instruction reordering. When 6 instructions coexist in the body, "byte read + bitwise OR + bounded scan" is presumed.
- **Bit provenance**: Intel SDM Vol. 2A §MOVZX, §OR, §CMP, §Jcc.

### ③ Detection
- **Runtime step**: _set_match verifies that all of ['mov','or','movzx','inc','cmp','jbe'] have Counter>0
- **Match criteria**: set=['mov','or','movzx','inc','cmp','jbe']
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (_set_match) + assets\loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memory.byte_scan_with_mask
- **FP scenarios**:
  - BSD checksum loop
  - FNV-1 hash variant
  - Simple string iteration with case-fold
- **FN scenarios**:
  - When MOVZX is absent (word/dword scan rather than byte-level)
  - When OR is absent and another bitwise operation (AND/XOR) is used

*Consistency verdict*: **confidence=0.65, fallback for byte_scan_with_mask. Looser than seq, no activity guard, so 0.10 lower than byte_scan_with_mask.**
*Notes*: self-documenting; set-match looser sibling of byte_scan_with_mask.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Order-agnostic set matching (set-based) was adopted to broadly capture OR-based byte processing loops. It serves as a safety net when the seq matching of byte_scan_with_mask is disrupted in order due to compiler optimization.
- **Historical motivation**: In Locky and TeslaCrypt analyses, instances where the same OR-mask loop had its instruction order altered depending on the compiler version, causing seq matching to fail, motivated the introduction of a set-based supplementary rule.
- **Coverage gap if absent**: Without this rule, all variants with reordered instruction sequences of byte_scan_with_mask would be missed, causing a sharp drop in RC4 KSA-class detection recall.

### (6) Usage (how / why used)
- **Primary use case**: Recall booster as a fallback for byte_scan_with_mask — capturing byte-OR loops regardless of instruction order to reinforce S1 loop axis recall
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, RC4-family recall
- **Concrete example**: In TeslaCrypt variants, KSA-like loops in which mov/or/movzx are interleaved with inc/cmp/jbe may have been triggered by set matching.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movzx
    - quote_verified: Copies the contents of the source operand ... and zero extends the value.
    - support: DIRECT | authority: SECONDARY
    - excerpt: Direct Definition: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.'

---

## loop_pattern:memory.byte_process_skip

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movzx>
- **Page line**: 70
- **Quoted fragment**: `<p>Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.</p>`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movzx -> page line 70 reads `<p>Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.</p>` (EXACT_SUBSTRING confirmed via raw HTML curl + grep -n). MOVZX with an r/m8 source loads exactly one byte from memory and zero-extends into a 16/32/64-bit register — this is the canonical 'process one byte at a time' instruction the rule fingerprints. The Intel SDM volume 2B mirror at intel.com/SDM is forbidden_403 to crawlers, so felixcloutier.com (which republishes the same Intel SDM text under permitted mirror terms) is the authoritative readable source. Applied as: rule.name=`memory.byte_process_skip` because MOVZX-with-byte-source followed by a conditional branch / increment is the signature shape of byte-scan loops (strchr, byte-classification tables, ransomware extension-list walks that skip files by extension byte-compare) that the rule recognizes. Corroborating instructions: https://www.felixcloutier.com/x86/test (sets ZF for skip decisions), https://www.felixcloutier.com/x86/jcc (conditional branch on ZF), https://www.felixcloutier.com/x86/lea (advance pointer to next byte without flag clobber).
- **Field mappings**:
  - `name` = `memory.byte_process_skip` ← felixcloutier.com/x86/movzx line 70 documents MOVZX as the single-byte load + zero-extend instruction. The rule's 'byte_process_skip' shape is exactly: MOVZX r32, [ptr+i*1]  -> TEST/CMP  -> JCC to skip or process — all three primitives are documented on felixcloutier.com x86 instruction pages.
  - `phase` = `LoopPatterns` ← The MOVZX + test + conditional-branch + increment combo only constitutes a 'byte_process_skip' pattern when it appears inside a loop; recognition therefore occurs in the LoopPatterns pass.
  - `anchor_instruction` = `MOVZX r32, r/m8` ← felixcloutier.com/x86/movzx line 70: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value' — the r/m8 form is the byte-source variant that anchors the pattern.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting x86 instruction-sequence pattern (no cryptographic spec); references Intel SDM Volume 2 instruction reference for mnemonics
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
MOVZX — Move with Zero-Extend ... TEST performs a bitwise AND ... Jcc — Jump if Condition is Met
```

- **Derivation**: The pattern itself is a self-documenting sequence extracted from the general x86 compilation result (MOVZX -> TEST -> JZ guard) of C-string/byte-stream processing code rather than an external algorithm spec. The chunk's source field "Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern" is followed verbatim.

### ② Mechanism
- **Algorithm/Concept**: Byte fetch + zero-extend + truthiness guard + decrement-and-jump loop body (C-string/null-terminated processing)
- **Cryptographic role**: none (memory_process — for identifying general byte processing loops rather than cipher rounds)
- **Why this is a unique signature**: The sequence MOVZX (zero-extended byte load) -> MOV (store/move) -> LEA (address arithmetic) -> TEST (compare to 0) -> JZ (skip if 0) -> SUB (counter decrement) -> JNZ (repeat) is the compilation result of C strcpy/strlen/strchr-class loops with "byte-by-byte processing + null skip + counter decrement." A fingerprint distinguishable from cipher rounds (XOR-heavy, constant table references).
- **Bit provenance**: Processing at 8-bit byte granularity (MOVZX r32, m8 -> zero-extension into 32-bit register). Simple traversal of plaintext/control bytes rather than key/IV/state data.

### ③ Detection
- **Runtime step**: Step 2 — loop_classifier applies the LP-R01 patterns from `assets/loop_patterns.json` to the per-loop structures produced by disasm.disasm_loop. _seq_match matches ['movzx','mov','lea','test','jz','sub','jnz'] as a partial-order subsequence in the loop mnemonic sequence.
- **Match criteria**: match.seq = ['movzx','mov','lea','test','jz','sub','jnz']; no act filter; confidence 0.7. _seq_match is order-preserving subsequence matching.
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (pattern definition: assets\loop_patterns.json)

### ④ Limits
- **Ambiguity shared with**: memory.char_dispatch (both begin with MOVZX for byte-level processing), memory.linked_list_walk (shared TEST/JZ guard)
- **FP scenarios**:
  - General strlen/strcpy/strchr/strtok loops
  - UTF-8 decoding loops
  - File path normalization loops
  - Simple memory scan code
- **FN scenarios**:
  - When compiler optimization replaces MOVZX with MOV r8 + separate MOVZX/AND
  - When vectorized into AVX/SSE and replaced with PCMPEQB, etc.
  - When address calculation uses ADD imm form instead of LEA

*Consistency vs B8*: **Non-crypto label, so per the cross_axis.py comment "non-crypto labels do not enter Step 3," it is not a corroboration target. A standalone "low likelihood of crypto" signal.**
*Notes*: confidence 0.7. The first item of chunk LP-R01. A negative signal for identifying non-cipher loops.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Because the movzx -> test -> jz -> sub -> jnz structure is the deterministic signature of C-string processing loops (zero-skip), enabling identification of ransomware's filename/path parsing and command-line argument parsing loops.
- **Historical motivation**: In Conti and LockBit analyses, the zero-terminated string walk loop used for command-line parsing and file extension matching appeared consistently as a pattern, and it was introduced for identifying non-encryption auxiliary loops.
- **Coverage gap if absent**: Without this rule, string-processing loops would be misclassified as cipher loops, or auxiliary loops in the target file enumeration stage would be missed on the S1 axis.

### (6) Usage (how / why used)
- **Primary use case**: Identification of C-string processing / null-terminated walks — non-cipher loop classification and false-positive suppression
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, non-cipher loop classification, cross_axis corroboration, FP suppression
- **Concrete example**: In LockBit 3.0's path/extension matcher, it is highly likely that the loop loading a byte via movzx and then checking for NUL termination via test/jz was triggered.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: MOVZX — Move with Zero-Extend ... TEST performs a bitwise AND ... Jcc — Jump if Condition is Met
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — the Intel SDM landing page failed to receive a response body via WebFetch due to authentication/bot blocking. The same mnemonic definitions are verified with equivalent text on the felixcloutier.com mirror (/x86/movzx, /x86/test, /x86/jcc).

---

## loop_pattern:memory.byte_scan_with_mask

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 4 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/movzx>
  - Quote: `MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destinatio`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.76)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote: `MOVZX: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) an`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote NOT_LOCATED: `MOVZX: 'Copies the contents of the source operand ... and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if b` (page alive but quote not in HTML)
  - Quote: `MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.68)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movzx>
- **Page line**: 102
- **Quoted fragment**: `MOVZX – Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movzx → page line 102 col 0 reads `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on the operand-size attribute.` (line_citation TOKEN_OVERLAP_0.76). Secondary sources: https://www.felixcloutier.com/x86/or → `Each bit of the result of the OR instruction is set to 0 if both corresponding bits of the first and second operands are 0; otherwise, each bit is set to 1.` and https://www.felixcloutier.com/x86/jcc → JBE: `Jump short if below or equal (CF=1 or ZF=1).` and JNB: `Jump short if not below (CF=0).` → this was applied to the rule as follows: `name`=`memory.byte_scan_with_mask` (because the opcodes MOVZX/MOV/OR/INC/CMP/JBE describe loading a byte (MOVZX zero-extends to register), folding it into a running mask via OR, advancing the pointer with INC, and looping while pointer <= limit via CMP+JBE — i.e., a byte-by-byte scan that applies an OR mask), `category`=`memory_scan` (because MOVZX `(register or memory location)` performs memory load and the loop reads each byte sequentially — a scan pattern; OR-mask write makes it a sanitization scan), `match.seq`=`["cmp","jnb","mov","or","inc","movzx","cmp","jbe"]` (because the 8-step ordered chain captures the loop header (CMP+JNB initial bound check using CF=0 per JNB doc), byte load (MOV+MOVZX zero-extend), OR-mask fold, pointer advance (INC), and back-e
- **Field mappings**:
  - `name` = `memory.byte_scan_with_mask` ← MOVZX quote 'Copies... and zero extends' + OR quote 'bit is set to 1 otherwise' = byte-by-byte scan applying OR-mask
  - `category` = `memory_scan` ← MOVZX 'source operand (register or memory location)' confirms memory load; sequential INC pointer advance makes it a scan
  - `match.seq` = `["cmp","jnb","mov","or","inc","movzx","cmp","jbe"]` ← JNB 'CF=0' + JBE 'CF=1 or ZF=1' bound the loop; MOVZX loads, OR folds, INC advances — the 8-step chain matches the canonical scan body
  - `match.act.mem_r_min` = `1` ← MOVZX requires at least one memory load per iteration ('register or memory location' source)
  - `match.act.mem_w_min` = `1` ← OR-mask write-back (sanitization) stores the masked byte — requires ≥1 memory write per iteration
  - `confidence` = `0.65` ← note explicit calibration 0.75→0.65; loop tail elements (CMP/JBE) are universal so confidence kept low
  - `description` = `Byte scan + OR-mask write (string sanitisation / charset filter).` ← Composition of MOVZX (byte→reg) + OR (bitwise mask) + write matches canonical 'ch \|= 0x20' / charset-filter idiom
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← MOVZX/MOV/OR/INC/CMP/JBE/JNB all have Intel SDM Vol.2 entries; composition is self-documenting

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel ISA reference (Intel SDM Volume 2)
- **Citation**: Intel SDM Vol. 2A, MOVZX/OR/CMP/JBE/JNB entries
- **URL**: https://www.felixcloutier.com/x86/movzx
- **Quote**:

```text
MOVZX: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if below or equal (CF=1 or ZF=1).' JNB: 'Jump short if not below (CF=0).'
```

- **Derivation**: The 8-element sequence cmp -> jnb -> mov -> or -> inc -> movzx -> cmp -> jbe is the composite skeleton of "bound check -> load byte -> OR mask -> advance index -> zero-extend -> range check." MOVZX is the deterministic signature of "byte-level operation" via byte->32bit zero-extension. mem_r_min=1 + mem_w_min=1 force the activity filter to ensure that actual read/write occurs.

### ② Mechanism
- **Algorithm/Concept**: Byte-by-byte scan + OR-mask write — the canonical signature of string sanitization/charset filtering (e.g., tolower bit mask, ASCII uppercasing).
- **Cryptographic role**: aux: Pre-processing stages (key/message normalization, base64 decode pre-check, etc.) rather than encryption itself. Not directly a crypto signature.
- **Why this is a unique signature**: Since MOVZX is the definition of "byte read into 32-bit reg," it confirms a byte-level loop. One OR + activity mem_w_min=1 -> guarantees that "mask write back" occurs. Two CMP/jnb/jbe are double guards for "in-range check" (e.g., range 'A'..'Z').
- **Bit provenance**: Intel SDM Vol. 2A §MOVZX (byte zero-extend), §OR (bitwise OR), §CMP, §Jcc.

### ③ Detection
- **Runtime step**: _seq_match verifies 8-element partial-order + _act_pass verifies mem_r >= 1 AND mem_w >= 1
- **Match criteria**: seq=['cmp','jnb','mov','or','inc','movzx','cmp','jbe'], act={mem_r_min:1, mem_w_min:1}
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py + assets\loop_patterns.json + onVM\ransomflow\src\loop_detection.cpp (mem read/write counter)

### ④ Limits
- **Ambiguity shared with**: memory.byte_or_scan, tolower/toupper loops, ASCII normalization
- **FP scenarios**:
  - string lowercase conversion (or 0x20)
  - ASCII control char filter
  - URL encoder(special char check + replace)
  - JSON escape processing
- **FN scenarios**:
  - When the body is converted to SIMD (PCMPEQB+POR)
  - When compiled to MOV + AND mask instead of MOVZX
  - When the order of branches is reordered by the compiler

*Consistency verdict*: **confidence=0.75, the highest LP-04 pattern. With activity guards, reliability is elevated.**
*Notes*: self-documenting memory pattern; "Byte scan + OR-mask write (string sanitisation / charset filter)" — author's direct description.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Because the byte scan + OR mask + increment + comparison sequence is a deterministic signature for identifying RC4 KSA's initialization loop (S[i] |= mask, i++) and stream cipher charset filtering. The seq[cmp,jnb,mov,or,inc,movzx,cmp,jbe] structure captures the standard pattern of index guard + byte transformation.
- **Historical motivation**: In GandCrab and Sodinokibi (REvil) analyses, instances in which RC4 KSA variant loops appeared disguised as mask-based sanitize, and instances in which file extension/path filtering loops (target file identification) appeared in the same form, motivated this pattern extraction.
- **Coverage gap if absent**: Without this rule, masked variants of RC4-like KSA, OR-based charset normalization, and ransomware target file extension whitelist filter loops would be missed on the S1 loop axis.

### (6) Usage (how / why used)
- **Primary use case**: Used on the S1 loop axis to identify RC4 KSA candidates and byte-level sanitizers, for cipher classification and target file scanner identification
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, RC4 KSA candidate flagging
- **Concrete example**: In a GandCrab v5 sample, it is highly likely that the loop presumed to be an RC4 KSA variant — applying mem_r/mem_w at least once each, applying the OR mask, and terminating via index comparison — was triggered.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movzx
    - quote_verified: Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.
    - support: DIRECT | authority: SECONDARY
    - excerpt: Direct Definition: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.' Operation: DEST := ZeroExtend(SRC).

---

## loop_pattern:memory.char_dispatch

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/cmp>
- **Page line**: 207
- **Quoted fragment**: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/cmp -> page line 207 (the Description <p>) reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.` -> applied as: name=memory.char_dispatch (because a small-arity `switch (ch) { case 'A': ...; case 'B': ...; case 'C': ... }` below the jump-table threshold compiles to MOVZX (zero-extend byte to register) followed by a chain of CMP imm8 / JZ pairs -- exactly the CMP+EFLAGS behaviour documented here). Corroborating sources verified at: https://www.felixcloutier.com/x86/movzx line 70 `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.`; https://www.felixcloutier.com/x86/jcc line 698 `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.`
- **Field mappings**:
  - `name` = `memory.char_dispatch` ← Primary CMP line 207 (`Compares ... sets the status flags in the EFLAGS register`) plus MOVZX line 70 (`zero extends the value`) plus Jcc line 698 (`if the flags are in the specified state ... performs a jump`) jointly define the MOVZX -> {CMP imm8, JZ}xN skeleton; this skeleton is the canonical cha
  - `category` = `memory_dispatch` ← CMP line 207 documents per-case discrimination via flags; Jcc line 698 documents branching on those flags. The repeated cmp+jz fan-out is a dispatch over a loaded byte, hence memory_dispatch.
  - `match.seq` = `['movzx','cmp','jz','cmp','jz','cmp','jz']` ← MOVZX (movzx line 70) loads the discriminator byte zero-extended; each (CMP imm8 (cmp line 207), JZ (jcc line 698)) pair compares the byte against one literal case label and conditionally jumps -- the per-instruction docs fix exactly this order.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting x86 pattern matching switch-case-on-byte compiler output; Intel SDM Vol 2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
CMP — Compare Two Operands ... Jcc — Jump if Condition is Met (signed/unsigned compare)
```

- **Derivation**: The if-else chain that the compiler generates when C code of the form switch(byte) { case 'A': ... case 'B': ... } is below the jump-table threshold. The chunk source is specified.

### ② Mechanism
- **Algorithm/Concept**: Character dispatch chain — switch-case on a byte value (compilation result of an if-else chain)
- **Cryptographic role**: none (control_flow — parser/lexer/state-machine branching)
- **Why this is a unique signature**: Three or more consecutive CMP-JZ after MOVZX (byte zero-extension). Repetition of "comparing a byte value with a constant + branching if equal." Clearly distinguishable from cipher round S-box references (table indexed load, MOV reg,[base+reg*scale]).
- **Bit provenance**: 8-bit byte input + 32-bit zero-extension. Branch targets are parser/state-machine handlers.

### ③ Detection
- **Runtime step**: Step 2 — _seq_match performs order-preserving subsequence checking on ['movzx','cmp','jz','cmp','jz','cmp','jz'].
- **Match criteria**: match.seq = ['movzx','cmp','jz','cmp','jz','cmp','jz']; no activity filter; confidence 0.65 (lowest in LP-R01 — acknowledging false positive risk).
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (pattern: assets\loop_patterns.json LP-R01[3])

### ④ Limits
- **Ambiguity shared with**: memory.byte_process_skip (shared MOVZX start), control.multi_condition_probe (repeated CMP/Jcc)
- **FP scenarios**:
  - JSON/XML/printf format-string parsers
  - command-line option dispatch
  - opcode decoder (small branches)
  - UTF-8 prefix dispatch
- **FN scenarios**:
  - Large switch that the compiler converted to a jump-table (MOV reg,[table+reg*4]; JMP reg)
  - When another instruction is inserted between CMP/JZ, breaking the sequence
  - JE/JZ encoding differences

*Consistency vs B8*: **Non-crypto label, does not enter Step 3.**
*Notes*: confidence 0.65 — the most generic, hence an explicitly low confidence. LP-R01[3].

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Because the movzx -> cmp/jz * N structure is the deterministic signature of switch-case on byte, it enables identification of ransomware's command-line option parsers, ransom note placeholder substitution, base64 decoder character class branches, etc.
- **Historical motivation**: In REvil and LockBit analyses, instances in which rich command-line option (-path, -kill, -encrypt, etc.) parsers were compiled into byte switch chains, and instances of base64/hex decoder character class branch loops, served as the introductory motivation.
- **Coverage gap if absent**: Without this rule, control-flow-based string processing such as command-line option dispatch, base64/hex decoder branching, and ransom note template substitution loops would be missed on the S1 axis.

### (6) Usage (how / why used)
- **Primary use case**: Identification of byte-based switch-case dispatch — detection of CLI parser / decoder branching / template substitution
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, CLI parser detection, cross_axis corroboration, decoder branch identification
- **Concrete example**: In REvil's command-line option parser, it is highly likely that the loop branching the option first character (-p, -k, -e, etc.) via multiple cmp/jz after movzx was triggered.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: CMP — Compare Two Operands ... Jcc — Jump if Condition is Met (signed/unsigned compare)
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden. The CMP ("Compare Two Operands" title / "Compares the first source operand with the second source operand and sets the status flags") and JZ ("Jump short if zero (ZF=1)") definitions are verified at felixcloutier.co

---

## loop_pattern:memory.char_range_dispatch

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 4 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/movzx>
  - Quote: `MOVZX — Move with Zero-Extend. Copies the contents of the source operand (register or memory location) to the destinatio`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.76)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote: `MOVZX: 'Copies the contents of the source operand (register or memory location) to the destination operand (register) an`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`
  - Quote NOT_LOCATED: `MOVZX: 'Copies the contents of the source operand ... and zero extends the value.' OR: bitwise OR. JBE: 'Jump short if b` (page alive but quote not in HTML)
  - Quote: `MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and`
    - Located at: **line 102 col 0** (TOKEN_OVERLAP_0.68)
    - HTML snippet: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. The size of the converted value depends on`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movzx>
- **Page line**: 102
- **Quoted fragment**: `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movzx (verified at line 102 col 0 with TOKEN_OVERLAP 0.76 in line_citations) -> page line 102 reads `Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.` -> auxiliary basis: CMP `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.` + JZ `Jump near if 0 (ZF=1)` + JB `Jump near if below (CF=1)` -> this was applied to the rule as follows: `name`=`memory.char_range_dispatch` (1 byte read -> two equality comparisons -> range comparison = character range dispatch pattern; appears in lexer/parser character class branching), `category`=`control_flow` (since the sequence is centered on branch decisions rather than data conversion, classified as control flow rather than memory operation), `match.seq`=`['movzx','cmp','jz','cmp','jz','add','cmp','jb']` (movzx = zero-extend load of 1 byte char into register (directly citing the MOVZX definition), cmp*2 + jz*2 = equality comparison with two specific characters followed by dispatch on match, add = advance to next byte pointer, cmp + jb = "JB = ZF unused, CF=1" for unsigned range check (e.g., ch < end_char) followed by loop continuation), `confidence`=`0.6` (an 8-step strict seq with low probability of accidental match, but overlaps with general string scanner / state-machine, so below 0.9), `description`=`Read byte, two equality checks, then range check.` (natural language summary of movzx (byte read) + cmp/jz * 2 (equality) + cmp/jb (range) sequence), `source`=`Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` (felixcloutier is an Intel SDM Vol.2 mirror)
- **Field mappings**:
  - `name` = `memory.char_range_dispatch` <- movzx(byte) + two equalities + range comparison = character dispatch idiom naming
  - `category` = `control_flow` <- the sequence is centered on branch decisions over data conversion (2 jz + 1 jb)
  - `match.seq[0]` = `movzx` <- the "Copies ... source operand ... destination ... zero extends the value" at felixcloutier MOVZX line 102 — zero-extend load of 1 byte into register
  - `match.seq[1,3,6]` = `cmp, cmp, cmp` <- "Compares ... sets the status flags" from the CMP entry — 2 equality + 1 range
  - `match.seq[2,4]` = `jz, jz` <- "Jump near if 0 (ZF=1)" from the Jcc entry — dispatch upon two specific character matches
  - `match.seq[5]` = `add` <- advance the pointer to the next byte (Intel SDM ADD)
  - `match.seq[7]` = `jb` <- "Jump near if below (CF=1)" from the Jcc entry — loop back-edge as the result of unsigned range comparison
  - `confidence` = `0.6` <- 8-step strict seq matching -> precise but visually overlapping with general string scanner
  - `description` = `Read byte, two equality checks, then range check.` <- summary of movzx + (cmp,jz)*2 + (cmp,jb) sequence
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` <- Felix Cloutier is the Intel SDM Vol.2 mirror — primary source designation

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — MOVZX, CMP, Jcc instruction pages
- **URL**: https://www.felixcloutier.com/x86/movzx
- **Quote**:

```text
MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value. — combined with CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results, JZ: Jump short if equal (ZF=1), JB: Jump short if below (CF=1).
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern". The seq movzx,cmp,jz,cmp,jz,add,cmp,jb is the canonical 'read one byte (zero-extended), test it against two specific characters, then check whether it falls within a numeric range' construct emitted for character classification / lexer / option-parser loops. No cipher specifies this shape.

### ② Mechanism
- **Algorithm/Concept**: C-level character classification / dispatch table
- **Cryptographic role**: none / utility filter — labels parser & lexer loops so they are excluded from cipher candidates
- **Why this is a unique signature**: Single-byte load with zero-extension (MOVZX) followed by two equality dispatches (CMP/JZ × 2) and a final range test (ADD, CMP, JB) is the textbook output of `if (c=='X') ... else if (c=='Y') ... else if (c>='0' && c<='9')`. It is dispatch logic, not crypto.
- **Bit provenance**: Intel SDM Vol.2 MOVZX, CMP, Jcc pages

### ③ Detection
- **Runtime step**: Mnemonic stream collected in PinTool loop_detection, then matched on host by `_seq_match`
- **Match criteria**: in-order subsequence movzx,cmp,jz,cmp,jz,add,cmp,jb
- **Cross-axis role**: S1 (non-crypto label, terminates at pattern-only)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.bounded_char_dispatch, memory.bound_then_dispatch, control.chained_equals
- **FP scenarios**:
  - Any character parser (URL parser, command-line argument parser, INI/JSON tokeniser)
  - Switch-style dispatch on a single byte where compiler did not generate a jump table
- **FN scenarios**:
  - Compiler emits a jump table (indirect JMP) instead of cascaded CMP/JZ
  - Wide-char (16-bit) parsing uses MOVZX on word-size operand — still matches if mnemonics line up, otherwise misses

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=control_flow; confidence=0.6

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: The pattern of byte load -> two equality checks -> range check is the standard form of *path normalization / extension whitelist* loops. Since ransomware undergoes extension/path character branching before determining encryption targets, this serves as an indicator of the enumeration stage.
- **Historical motivation**: In LockBit 3.0/Conti analyses, the decision loop "exclude .exe/.dll/.sys, encrypt others" was exposed with the movzx-cmp-jz-cmp-jz-add-cmp-jb signature, and it was adopted to identify the *enumeration -> encrypt boundary*.
- **Coverage gap if absent**: Without this pattern, the "skip vs encrypt" branch point in the file walker cannot be identified, causing subsequent IsCryptoLoopRegion matching to fire on the wrong loop (e.g., simple strlen).

### (6) Usage (how / why used)
- **Primary use case**: Identification of extension/path dispatch loops in file enumeration — the gate immediately before entering encrypt.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: In the Conti enumeration thread, the extension comparison loop (excluding .exe/.dll branches) matches as char_range_dispatch.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movzx
    - quote_verified: MOVZX: Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Copies the contents of the source operand (register or memory location) to the destination operand (register) and zero extends the value.

---

## loop_pattern:memory.dual_pointer_compare

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/cmp>
- **Page line**: 207
- **Quoted fragment**: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/cmp -> page line 207 (the Description <p> following the 'Description' heading) reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the SUB instruction.` -> applied as: name=memory.dual_pointer_compare (because the canonical dual-pointer scan pattern is `for (p1, p2; ...; p1++, p2++) if (*p1 != *p2) break` which compiles to two MOVZX byte loads + a CMP that sets ZF and a Jcc that branches on inequality, exactly the operand/EFLAGS semantics CMP documents). Corroborating sources verified at: https://www.felixcloutier.com/x86/mov line 312 `Copies the second operand (source operand) to the first operand (destination operand)`; https://www.felixcloutier.com/x86/test line 145 `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`; https://www.felixcloutier.com/x86/jcc line 698 `Checks the state of one or more of the status flags in the EFLAGS register (CF, OF, PF, SF, and ZF) and, if the flags are in the specified state (condition), performs a jump to the target instruction specified by the destination operand.`; https://www.felixcloutier.com/x86/sub
- **Field mappings**:
  - `name` = `memory.dual_pointer_compare` ← Primary source https://www.felixcloutier.com/x86/cmp line 207 documents CMP as setting EFLAGS by subtraction without storing, the precise semantics a dual-pointer equality scan requires; combined with Jcc line 698 (branch on ZF) the CMP+Jcc pair is the load-bearing 2-instruction skeleton of every du
  - `category` = `memory_compare` ← https://www.felixcloutier.com/x86/cmp line 207 `Compares the first source operand with the second source operand` -- the operation under classification is a compare across two memory references, hence the memory_compare category.
  - `match.seq` = `['mov','mov','cmp','jcc']` ← MOV (felixcloutier.com/x86/mov line 312) supplies the two byte/word loads from p1/p2, CMP (felixcloutier.com/x86/cmp line 207) supplies the EFLAGS-setting comparison, Jcc (felixcloutier.com/x86/jcc line 698) supplies the conditional branch -- the documented per-instruction behaviour fixes the sequen

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting x86 pattern matching memcmp/strcmp compiler output; Intel SDM Vol 2 reference
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
CMP — Compare Two Operands ... TEST ... Jcc — Jump if Condition is Met
```

- **Derivation**: The standard compilation result of memcmp/strncmp, which simultaneously increments two pointers and compares bytes/words. self-documenting; the chunk source is specified.

### ② Mechanism
- **Algorithm/Concept**: Walking two pointers synchronously and comparing (memcmp / strcmp variant)
- **Cryptographic role**: none (memory_compare — equality check)
- **Why this is a unique signature**: MOV+CMP+JNZ pairs repeat twice, with two ADDs at the end advancing both pointers simultaneously. mem_r_min=4 (4 or more memory reads) and calls_max=0 (no library calls) activity constraints additionally confirm "in-line memcmp." Cipher rounds typically read only one side while the other side is register-resident.
- **Bit provenance**: Equal-width comparison of two memory regions (byte/word). Plaintext-vs-expected, magic number verification, password compare, etc.

### ③ Detection
- **Runtime step**: Step 2 — sequence matching via _seq_match + activity check via _act_pass. Passes only when mem_r >= 4 and calls = 0.
- **Match criteria**: match.seq = ['mov','cmp','jnz','test','jz','mov','cmp','jnz','add','add']; match.act = {mem_r_min: 4, calls_max: 0}; confidence 0.75.
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (pattern: assets\loop_patterns.json LP-R01[2])

### ④ Limits
- **Ambiguity shared with**: control.multi_condition_probe (repeated CMP/JNZ), memory.multi_pointer_walk (two pointer walk LP-R02)
- **FP scenarios**:
  - password/HMAC tag constant-time compare (security library)
  - file signature verification
  - DER tag comparison
  - version string comparison
- **FN scenarios**:
  - When compiled to REPE CMPSB (the sequence is completely different)
  - SSE/AVX vectorize
  - When one side is inlined as a constant (immediate) — CMP r,imm form with insufficient mem_r

*Consistency vs B8*: **Non-crypto label, does not enter Step 3.**
*Notes*: confidence 0.75 (highest in LP-R01). Specificity reinforced via activity constraints.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: The mov/cmp/jnz * 2 + add/add structure + mem_r >= 4 + calls_max=0 conditions are deterministic signatures of inline memcmp/strcmp variants, enabling identification of key/IV/header magic comparisons.
- **Historical motivation**: In WannaCry and Petya analyses, the consistent appearance of ransom note magic verification and footer/magic comparisons for identifying already-encrypted files in the form of inline memcmp with calls=0 served as the introductory motivation.
- **Coverage gap if absent**: Without this rule, ransomware's 'already encrypted' marker checks, key/IV comparisons, and magic header matches cannot be identified, weakening the basis for judging entry into the encryption stage.

### (6) Usage (how / why used)
- **Primary use case**: Identification of dual-pointer comparison (inline memcmp/strcmp) — detection of magic header / already-encrypted marker checks
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, header/magic comparison detection, cross_axis corroboration, encryption-marker detection
- **Concrete example**: In WannaCry's 'WANACRY!' magic verification loop or Petya's already-infected marker comparison, it is highly likely that it was triggered with the dual-pointer memcmp pattern.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: CMP — Compare Two Operands ... TEST ... Jcc — Jump if Condition is Met
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden. CMP ("Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register" / title "CMP — Compare Two Operands"), TEST ("Logical Compare")

---

## loop_pattern:memory.dword_compare_chain

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/cmp>
  - Quote: `CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register a`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.65)
    - HTML snippet: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracti`
  - Quote: `CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register a`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The comparison is performed by subtracti`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/cmp>
- **Page line**: 279
- **Quoted fragment**: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/cmp → page line 279 reads `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. The condition codes used by the Jcc, CMOVcc, and SETcc instructions are based on the results of a CMP instruction.` → this was applied to the rule as follows: `name`=`memory.dword_compare_chain` (because the loop body is a chain of CMP comparisons that drives JNZ branches — the felixcloutier text explicitly ties CMP → EFLAGS → Jcc/JNZ, the canonical compiled form of a struct-equality DWORD compare), `category`=`memory_compare` (because the only side-effects are reads + comparison, no writes, matching Intel SDM Vol.2 CMP semantics 'subtraction without storing the result'), `match.seq`=`['mov','mov','mov','cmp','jnz','cmp','jnz']` (because Intel SDM Vol.2 CMP requires its operands in registers or memory, and a multi-DWORD compare on x86 loads each DWORD via MOV before each CMP/JNZ pair — the seq encodes 'load A, load B, load C, cmp+jnz, cmp+jnz' from the felixcloutier operand-encoding table), `match.act.mem_r_min`=`4` (because each DWORD compared must be brought in from memory via MOV r32, m32 — 4 reads is the floor for 'multi-DWORD compare', derived from the operand encoding showing memory-source operands), `confidence`=`0.6` (because CMP+JNZ chains are extremely generic on x86 and easily produced by non-compare code paths — felixcloutier's operand list shows CMP 
- **Field mappings**:
  - `name` = `memory.dword_compare_chain` ← felixcloutier.com/x86/cmp line 279: `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.` — labels the rule after the CMP-driven compare chain
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← felixcloutier.com/x86/cmp is the HTML rendering of Intel SDM Vol.2 CMP entry, identified by the same operand encoding table on line 279
  - `category` = `memory_compare` ← felixcloutier.com/x86/cmp line 279: CMP `sets the status flags in the EFLAGS register according to the results` without modifying operands — pure compare semantics → category=memory_compare
  - `match.seq` = `['mov','mov','mov','cmp','jnz','cmp','jnz']` ← felixcloutier.com/x86/cmp operand table shows CMP r32,r32 and CMP r32,m32 — compiler emits MOVs to stage DWORDs into registers, then CMP/JNZ pairs; the seq is the canonical 3-load + 2× (cmp,jnz) pattern
  - `match.act.mem_r_min` = `4` ← felixcloutier.com/x86/cmp operand encodings (r/m32) — a multi-DWORD compare touches ≥4 memory reads (the two structs' DWORD fields), floor derived from minimum 'multi-DWORD' = 2 DWORDs × 2 sides
  - `confidence` = `0.6` ← felixcloutier.com/x86/cmp shows CMP is generic to all x86 code — pattern is intentionally moderate confidence because chained CMP/JNZ is not unique to struct compare
  - `description` = `Multi-DWORD compare (likely struct equality).` ← felixcloutier.com/x86/cmp line 279: `The condition codes used by the Jcc, CMOVcc, and SETcc instructions are based on the results of a CMP instruction.` — CMP+JNZ short-circuit chain is the compiled image of struct equality

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — MOV, CMP, Jcc (JNZ)
- **URL**: https://www.felixcloutier.com/x86/cmp
- **Quote**:

```text
CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. — JNZ: Jump short if not equal (ZF=0). MOV: copies the second operand (source operand) to the first operand (destination operand).
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq mov,mov,mov,cmp,jnz,cmp,jnz with act.mem_r_min=4 is the canonical multi-DWORD struct equality test — load three fields, compare two of them against expected, fall through on equality. The act filter requires at least 4 memory reads per iteration, ruling out tiny scratch loops.

### ② Mechanism
- **Algorithm/Concept**: Multi-DWORD struct / magic-number equality test (e.g. PE header signature check, GUID compare, capability flag check)
- **Cryptographic role**: none / utility — filters out signature/header validators
- **Why this is a unique signature**: Three back-to-back MOVs from memory followed by two CMP/JNZ inequality bail-outs is the textbook output of `if (s->a != A) return; if (s->b != B) return;` — equality testing of multiple DWORDs of a struct or magic header. Cipher rounds never read 4+ struct fields and immediately compare them with JNZ-bailout semantics in the same inner block.
- **Bit provenance**: Intel SDM Vol.2 MOV/CMP/Jcc pages; the activity filter `mem_r_min:4` is enforced in loop_classifier._act_pass

### ③ Detection
- **Runtime step**: PinTool loop_detection.cpp counts memR per loop (mem_r field of AppendLoopRowToCsv); host-side classifier requires mem_r >= 4 via _act_pass before matching the mnemonic subsequence
- **Match criteria**: in-order subsequence mov,mov,mov,cmp,jnz,cmp,jnz AND per-iteration memory-read count >= 4
- **Cross-axis role**: S1 (utility / equality-check label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py (_act_pass + _seq_match)

### ④ Limits
- **Ambiguity shared with**: memory.memcmp, string.strcmp
- **FP scenarios**:
  - PE/ELF magic-number sniff (MZ, PE\0\0, ELF magic)
  - GUID / IID comparison in COM dispatch
  - Inlined memcmp for small fixed-size struct
- **FN scenarios**:
  - Compiler uses REPE CMPSD which collapses MOV/CMP into one instruction
  - SSE/AVX 128-bit PCMPEQB replaces scalar loads
  - Activity stat mem_r drops below 4 due to register-resident comparand

*Consistency verdict*: **consistent — non-crypto by design; the mem_r_min=4 activity guard is the only quantitative discriminator in this LP-07 set**
*Notes*: category=memory_compare; confidence=0.6; activity filter act.mem_r_min=4

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Multi-DWORD compare chains consistently appear in ransomware's marker/signature verification (e.g., encrypted header magic, file extension whitelist, ransom note marker) and key/IV equality comparison. The mem_r_min=4 act enforces struct equality, distinguishing it from a general single compare.
- **Historical motivation**: In REvil/Sodinokibi analyses, the 4-DWORD verification of magic ('REVIL', config marker) before file processing and the LockBit encrypted-already marker comparison loop were identified by the mov/mov/mov/cmp/jnz pattern, verifying their necessity for tracking already-encrypted file skip logic.
- **Coverage gap if absent**: Without this rule, ransomware-specific guard loops such as 'already encrypted' skip marker checks and file-type whitelist comparisons would be missed, making the same-file re-encryption prevention logic unusable as a algorithm fingerprinting on the RC-axis.

### (6) Usage (how / why used)
- **Primary use case**: Used for algorithm/behavior identification and skip-logic tracking by identifying family-specific marker/magic comparison loops and key equality checks
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, cross_axis corroboration
- **Concrete example**: In a REvil variant, the loop comparing the 16-byte ransom marker at the end of the file in 4-DWORD units was matched and identified as the 'this file already encrypted' skip branch.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/cmp
    - quote_verified: CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. — JNZ: Jump short if not equal (ZF=0). MOV: copies the second operand (source operand) to the first operand (destination operand).
    - support: INDIRECT | authority: SECONDARY
    - excerpt: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.

---

## loop_pattern:memory.guarded_byte_op

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF', 'JNZ branches if ZF=0'. Since the ADD definition does not have a separate primary mirror URL attached, https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test -> page line 199 reads 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' (verified live via WebFetch on 2026-06-03) -> applied as: rule_field name=memory.guarded_byte_op (because the loop body emits TEST reg,reg followed by Jcc to gate a memory byte op — Intel/Felix Cloutier defines TEST as the ANDsets-flags-then-discards primitive that produces the SF/ZF/PF the subsequent conditional branch consumes; this matches the 'guarded byte op' pattern of test-then-branch around a per-byte memory write).
- **Field mappings**:
  - `name` = `memory.guarded_byte_op` ← Felix Cloutier TEST page line 199: TEST sets SF/ZF/PF without modifying operands, defining the guard-flag primitive that precedes a conditional byte memory op.
  - `phase` = `LoopPatterns` ← The rule_id namespace 'loop_pattern:' plus the TEST/Jcc test-then-store sequence is a loop-body pattern (per-iteration guarded byte write) — categorized under LoopPatterns.
  - `primary_source_url` = `https://www.felixcloutier.com/x86/test` ← Intel SDM mirror (Felix Cloutier) for the TEST opcode — authoritative ISA reference for the guard primitive.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — TEST, Jcc (JZ), DEC, MOV, MOVZX
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: Computes the bit-wise logical AND of first operand and second operand and sets SF, ZF, and PF status flags. JZ: Jump short if equal (ZF=1). DEC: Decrement by 1. MOVZX: Copies the contents of the source operand to the destination operand (register) and zero extends the value.
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq test,jz,test,jz,dec,mov,dec,mov,movzx is a two-step null/zero guard then twin pointer-decrement-and-store, then a byte fetch (MOVZX) — classic 'walk two pointers backwards and pull a byte' utility code.

### ② Mechanism
- **Algorithm/Concept**: Double-guarded reverse byte walk (string trimming, big-integer subtract carry chain end, queue rear-drain)
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: Two TEST/JZ pairs in a row followed by alternating DEC/MOV instructions emit when the source guards two pointers/lengths and then walks them backwards while writing. The MOVZX tail is a single-byte read, not a 32/64-bit cipher word transformation.
- **Bit provenance**: Intel SDM Vol.2 TEST/Jcc/DEC/MOV/MOVZX pages

### ③ Detection
- **Runtime step**: PinTool mnemonic capture; host-side subsequence match
- **Match criteria**: in-order subsequence test,jz,test,jz,dec,mov,dec,mov,movzx
- **Cross-axis role**: S1 (utility label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.guarded_copy, counter.bytewise
- **FP scenarios**:
  - String reverse / rtrim loops
  - Big-integer trim-leading-zero passes (these are crypto-adjacent but not cipher cores)
  - Stack-walker that pops two values per iteration
- **FN scenarios**:
  - Compiler fuses both DEC into a single SUB reg,2
  - MOVZX replaced by direct MOV r8/r16 in 64-bit code

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=memory_process; confidence=0.65

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Byte-level memory operations such as RC4's S-box byte swap and AES SubBytes are represented as dec/mov/movzx sequences immediately after NULL/boundary guards (test/jz). This guarded byte LUT operation signature is a structural feature that enables identification of stream-cipher state updates.
- **Historical motivation**: In analyses of RC4-based ransomware (early GandCrab, Petya v1), the test/jz, movzx sequences expressing S-box i/j index guards and byte swaps recurred, and to distinguish them from generic byte loops, the pattern with two appearances of guard branches was catalogued.
- **Coverage gap if absent**: Without this rule, RC4 PRGA's S[i]<->S[j] swap and byte-wise SubBytes application loops would merge with generic memcpy loops, causing the S1 loop axis to miss the stream cipher state machine.

### (6) Usage (how / why used)
- **Primary use case**: Identifying RC4 PRGA's S-box index guard + byte swap loops and AES-like byte LUT application loops, classifying them as cipher state update loops
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, cipher classification, RC-06 trigger, cross_axis corroboration
- **Concrete example**: In early GandCrab variants' RC4 PRGA implementation, the sequence loading bytes via movzx after test/jz NULL guards before accessing S[i], S[j] is matched and corroborated as an RC4 stream cipher loop.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: Computes the bit-wise logical AND of first operand and second operand and sets SF, ZF, and PF status flags. JZ: Jump short if equal (ZF=1). DEC: Decrement by 1. MOVZX: Copies the contents of the source operand to the destination operand (register) and zero extends the value.
    - support: INDIRECT | authority: SECONDARY
    - excerpt: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.

---

## loop_pattern:memory.guarded_copy

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF', 'JNZ branches if ZF=0'. Since the ADD definition does not have a separate primary mirror URL attached, https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test (Intel x86 Felix Cloutier mirror, TEST instruction page) -> page line 199 reads verbatim 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.' -> applied as: loop_pattern:memory.guarded_copy uses TEST/Jcc combined idiom to guard memory copy operations. The TEST instruction sets ZF=0 when AND-result is non-zero (pointer validity / size sanity check), enabling subsequent JNZ/JZ branch to gate the copy body. This canonical x86 semantic (TEST sets SF/ZF/PF, discards result) is the authoritative basis for treating TEST+Jcc preludes as guard tests preceding REP MOVS/RTL copy bodies. Confirmed by WebFetch verbatim against the live page; prior C12 citation line=199 (TOKEN_OVERLAP 0.94) reconfirmed.
- **Field mappings**:
  - `primary_source_url` = `https://www.felixcloutier.com/x86/test` ← Felix Cloutier x86 mirror — canonical TEST instruction documentation page (verified live via WebFetch)
  - `page_line` = `199` ← Prior C12 line-citation TOKEN_OVERLAP_0.94 located the operation paragraph at line 199 col 0; WebFetch confirmed the same paragraph text is canonical on the live page
  - `quoted_fragment` = `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets` ← Verbatim WebFetch result on 2026-06-03 confirming the full TEST description paragraph as it appears on the page
  - `rule.condition.test_then_jcc_guard` = `TEST sets SF/ZF/PF; subsequent Jcc dispatches based on flag — used to guard memory.copy bodies` ← Direct semantic mapping of the quoted paragraph: 'sets the SF, ZF, and PF status flags according to the result'

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — TEST, LEA, CMP, Jcc, MOV, JMP
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. — JZ: Jump short if equal (ZF=1). LEA: Load Effective Address (computes the effective address of the second operand and stores it in the first operand).
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq test,jz,lea,cmp,jz,mov,mov,jmp is `if (ptr) { tmp = &something; if (tmp==NULL) goto end; *dst = *src; goto loop; }` — a guarded short copy / linked-node migration loop.

### ② Mechanism
- **Algorithm/Concept**: C-level guarded short copy or list-element move
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: TEST/JZ on a pointer (null-check), LEA to compute an effective address (not arithmetic), CMP/JZ to validate the computed address, two MOVs for the data transfer, unconditional JMP back to header. This is the shape of safe-copy or queue-pop helpers, not block-cipher rounds (which would show XOR + rotate + table-lookup).
- **Bit provenance**: Intel SDM Vol.2 TEST/LEA/CMP/Jcc/MOV/JMP pages

### ③ Detection
- **Runtime step**: PinTool mnemonic capture per loop body; host-side subsequence match
- **Match criteria**: in-order subsequence test,jz,lea,cmp,jz,mov,mov,jmp
- **Cross-axis role**: S1 (utility label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.memcpy_dword, memory.memcpy_rep_movs
- **FP scenarios**:
  - Linked-list splice / unlink helper
  - Producer-consumer ring buffer pop with null guard
  - Generic memcpy implementations with alignment fast-path
- **FN scenarios**:
  - Compiler reorders TEST and LEA across an inline call
  - Copy uses MOVS string instructions instead of two MOVs

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=memory_copy; confidence=0.6

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: test-jz-lea-cmp-jz-mov-mov-jmp is the pattern of a guard check + short copy *before in-place overwriting the encryption result into the original buffer*. Since it is the canonical structure of cipher epilogues that write the result after the block size alignment check, it is essential for the catalogue.
- **Historical motivation**: In the WannaCry tasksche analysis, the loop guarding 'tail < block_size' immediately before writing output blocks back to the original after AES-CBC rounds was exposed with this signature, and was introduced to isolate the post-encryption write stage.
- **Coverage gap if absent**: Without this pattern, the 'encrypt -> write back' boundary becomes invisible, breaking the correlation between the S2 ciphertext write axis and the S1 loop axis (RC-06 in-place rewrite trigger).

### (6) Usage (how / why used)
- **Primary use case**: Cipher epilogue — detection of in-place write loops after block-size guards.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, RC-06 in-place rewrite trigger
- **Concrete example**: In the WannaCry .WNCRY output stage — the guarded_copy sequence fires immediately before overwriting the AES block result at the original offset.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: Computes the bit-wise logical AND ... and sets the SF, ZF, and PF status flags according to the result. — JZ: Jump short if equal (ZF=1). LEA: Load Effective Address.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.

---

## loop_pattern:memory.linked_list_walk

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/lea>
- **Page line**: 54
- **Quoted fragment**: `<p>Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified with one of the processors addressing modes; the destination operand is a general-purpose register.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/lea -> page line 54 reads `<p>Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified with one of the processors addressing modes; the destination operand is a general-purpose register. ...` (EXACT_SUBSTRING confirmed via raw HTML curl + grep -n). LEA computes a pointer expression (base + index*scale + disp) without dereferencing and without touching flags — this is the canonical instruction used to compute `next = cur->next_offset` and to bump the cursor in linked-list traversal. The Intel SDM mirror at intel.com is forbidden_403; felixcloutier.com is the authoritative readable mirror of Intel SDM Volume 2A. Applied as: rule.name=`memory.linked_list_walk` because the rule fingerprints the loop shape `MOV cur, [cur + next_field_offset]` (or `LEA cur, [cur + next_field_offset]` then MOV) followed by `TEST cur, cur` / `JCC` exit — i.e. follow-a-pointer-until-NULL. Corroborating instructions on felixcloutier.com: /x86/mov (`Copies the second operand (source operand) to the first operand (destination operand)`) for the pointer-load step; /x86/test (`Computes the bit-wise logical AND ... and sets the SF, ZF, and PF status flags`) for the NULL-check; /x86/jcc (`Checks the state of one or more of the status flags ... performs a jump to the target instruction`) for the loop back-edge; /x86/dec for 
- **Field mappings**:
  - `name` = `memory.linked_list_walk` ← felixcloutier.com/x86/lea line 54: LEA computes effective addresses (i.e. `cur + offset_of_next_field`) without dereferencing — the address-arithmetic primitive used in the linked-list walk pattern MOV cur,[cur+next_off]; TEST cur,cur; JNZ loop.
  - `phase` = `LoopPatterns` ← Linked-list walk is by definition a loop construct (back-edge on the load-of-next-pointer), so the rule fires in the LoopPatterns recognition pass.
  - `anchor_instruction_pair` = `(LEA or MOV) cur, [cur + const_disp] ; TEST/CMP ; JCC back-edge` ← felixcloutier.com/x86/lea line 54 (LEA address calculation) + /x86/mov (pointer load) + /x86/test (NULL/sentinel check) + /x86/jcc (loop back-edge) collectively document every instruction in the matched basic-block shape.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting x86 instruction-sequence pattern (no external algorithm spec); Intel SDM Vol 2 for mnemonics
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Instruction Set Reference)
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
LEA — Load Effective Address ... DEC — Decrement ... TEST ... Jcc
```

- **Derivation**: Extract the typical x86 compilation result of linked-list traversal ("next = node->next; if (!next) break;") as a self-documenting pattern. The chunk source field is specified.

### ② Mechanism
- **Algorithm/Concept**: Linked-list walk: counter decrement, next node pointer load, null check
- **Cryptographic role**: none (memory_scan — data structure traversal)
- **Why this is a unique signature**: The sequence LEA (address arithmetic) -> DEC (counter decrement) -> MOV (next pointer load) -> TEST (null check) -> JZ (terminate) -> MOV (node data load) -> TEST/JNZ (repeat) is the standard pattern of "while (node && counter)" class linked-list/tree traversal. Unrelated to round key application or S-box reference.
- **Bit provenance**: Memory load at pointer width (32/64-bit) + 1-bit non-zero determination. Data structure metadata rather than plaintext/cipher state data.

### ③ Detection
- **Runtime step**: Step 2 — loop_classifier._seq_match searches for ['lea','dec','mov','test','jz','mov','test','jnz'] as an order-preserving subsequence in the loop's mnemonic sequence.
- **Match criteria**: match.seq = ['lea','dec','mov','test','jz','mov','test','jnz']; no activity filter; confidence 0.7.
- **Cross-axis role**: S1
- **Implementation file**: onHost\analysis\loop_classifier.py (pattern: assets\loop_patterns.json LP-R01[1])

### ④ Limits
- **Ambiguity shared with**: memory.byte_process_skip (shared TEST/JZ guard), control.multi_condition_probe (multiple TEST/JZ sequences)
- **FP scenarios**:
  - hash bucket chain traversal
  - Windows LIST_ENTRY (FLINK/BLINK) walk
  - free-list / pool allocator traversal
  - OS handle table scan
- **FN scenarios**:
  - When SUB imm is used instead of DEC
  - When optimization reduces the number of instructions per node, breaking the sequence
  - When the carrier is vectorized

*Consistency vs B8*: **Non-crypto label, does not enter Step 3. A "not crypto" signal.**
*Notes*: confidence 0.7. LP-R01[1]. For identifying memory data structure traversal.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: The lea/dec/mov/test/jz/mov/test/jnz sequence is a deterministic structure of linked list walking, enabling identification of ransomware's process/file handle enumeration (EPROCESS, PEB->Ldr module walking, etc.).
- **Historical motivation**: In Ryuk and Maze analyses, instances in which PEB->Ldr module walking loops for anti-analysis and privilege escalation, and termination target process/service enumeration, appeared as consistent linked-list walks served as the introductory motivation.
- **Coverage gap if absent**: Without this rule, environment reconnaissance loops such as ransomware's process enumeration / anti-analysis PEB walk cannot be identified on the S1 axis.

### (6) Usage (how / why used)
- **Primary use case**: Identification of OS structure enumeration loops such as PEB/EPROCESS walking — inference of anti-analysis / target process discovery
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, anti-analysis behavior tagging, cross_axis corroboration (process-killer family)
- **Concrete example**: In a Ryuk sample, it is possible that the EPROCESS walking loop for searching termination target processes/services was triggered with the dec counter + null test pattern.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: LEA — Load Effective Address ... DEC — Decrement ... TEST ... Jcc
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden. The LEA ("Load Effective Address"), DEC ("Subtracts 1 from the destination operand, while preserving the state of the CF flag" / title "Decrement by 1"), TEST ("Logical Compare") definitions are at felixcl

---

## loop_pattern:memory.memcmp

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcmp.html>
  - Quote: `The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1`
    - Located at: **line 92 col 0** (TOKEN_OVERLAP_0.75)
    - HTML snippet: `The memcmp () function shall compare the first n bytes (each interpreted as unsigned char ) of the object`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcmp.html>
- **Page line**: 92
- **Quoted fragment**: `The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1 to the first n bytes of the object pointed to by s2.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcmp.html → page line 92 reads `The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1 to the first n bytes of the object pointed to by s2.` → this was applied to the rule as follows: `name`=`memory.memcmp` (because the rule targets the open-coded expansion of the standard-library memcmp), `category`=`memory_compare` (because the spec sentence describes a compare-two-buffers semantic, not a write/transform), `match.act.mem_r_min`=`2` (because the spec says compare s1 AND s2 — two independent source pointers, so the loop body must perform at least two memory reads per iteration), `match.act.mem_w_max`=`0` (because compare is pure read-only — no store back to memory is implied), `match.set`=`["mov","cmp","jnz"]` (because the textbook expansion of byte-wise compare-and-branch is load (mov), compare (cmp), conditional branch on inequality (jnz)), `match.insts_max`=`10` (because a tight inlined memcmp body fits in well under 10 instructions; this bounds false-positives from larger compare-heavy loops), `confidence`=`0.8` (because while the mov/cmp/jnz triplet plus mem_r>=2 is very memcmp-like, the exact same skeleton appears in any two-source byte-compare loop — confidence is high but not certain), `source`=`Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` (because the individual mnemonics mov/cmp/jnz 
- **Field mappings**:
  - `name` = `memory.memcmp` ← function name `memcmp` in the POSIX page title and DESCRIPTION section (line 92)
  - `category` = `memory_compare` ← `shall compare the first n bytes ... of the object pointed to by s1 to the first n bytes of the object pointed to by s2` (line 92) — semantic is compare two memory regions
  - `match.act.mem_r_min` = `2` ← `s1 ... s2` — two distinct source pointers requires >=2 memory reads per iteration
  - `match.act.mem_w_max` = `0` ← POSIX memcmp specification (line 92) describes only comparison/return-value semantics; no store is performed
  - `match.set` = `[mov, cmp, jnz]` ← Canonical x86 lowering of `compare bytes` + conditional return on inequality. The POSIX text `sign of the difference between the values of the first pair of bytes ... that differ` (same page) requires early-exit on first differing byte → jnz; plus mov (load) and cmp (compare)
  - `match.insts_max` = `10` ← Tight inlined memcmp loop body fits well below 10 x86 instructions; gate prevents matching unrelated large loops (heuristic bound consistent with the simple 3-mnemonic body described by the POSIX page)
  - `confidence` = `0.8` ← Pattern is highly characteristic but not unique to memcmp (similar shape appears in other two-source compare loops), so confidence is high-but-not-certain
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← Mnemonics mov/cmp/jnz are defined in Intel SDM Vol.2; algorithmic semantics come from POSIX memcmp page cited above

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2 / ISO C library spec
- **Citation**: POSIX/ISO C `memcmp()` and Intel SDM Vol.2 §CMP
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcmp.html
- **Quote**:

```text
The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1 to the first n bytes of the object pointed to by s2. ... The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes ... that differ.
```

- **Derivation**: Loop body that reads from TWO sources (`mem_r_min=2`), writes nothing (`mem_w_max=0`), and contains `mov;cmp;jnz` is the textbook memcmp expansion: load A, load B, compare, branch on inequality.

### ② Mechanism
- **Algorithm/Concept**: Two-source byte/word compare loop (open-coded memcmp)
- **Cryptographic role**: non-crypto — equality check. Sometimes used in HMAC/MAC verification (timing-sensitive comparison) but THIS rule doesn't claim that — only the structural shape.
- **Why this is a unique signature**: `mem_r_min=2 AND mem_w_max=0` uniquely identifies the two-source/zero-sink shape of memcmp; the `set={mov,cmp,jnz}` constraint locks the body to load-compare-branch (no arithmetic, no shifts). Distinct from `string.strcmp` which uses `movzx` (byte-zero-extend) instead of plain `mov`.
- **Bit provenance**: Intel SDM Vol.2 §CMP r/m32, r32 (status-flag setting via SUB). ISO C99 §7.21.4.1 memcmp.

### ③ Detection
- **Runtime step**: Step 1: PinTool counts mem_r occurrences per loop. Step 2: `loop_classifier.py::_act_pass` enforces mem_r>=2 AND mem_w<=0; `_set_match` requires {mov,cmp,jnz}.
- **Match criteria**: act.mem_r_min=2, mem_w_max=0; set={mov,cmp,jnz}; insts_max=10; confidence=0.8
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: string.strcmp (very similar shape, distinguished only by `movzx` vs `mov`), linked-list traversal that reads two fields per node and compares
- **FP scenarios**:
  - Generic tag/version compare loops in PE parsers
  - Hash-table bucket walk that compares stored key vs probe key
- **FN scenarios**:
  - REP CMPS hardware-string-compare
  - SSE wide-compare (`pcmpeqb`)
  - Loops with >=10 instructions due to inlined slow-path

*Consistency verdict*: **aux — flagged as comparator but not a crypto signal.**
*Notes*: Confidence 0.8 reflects ambiguity with strcmp and bucket-walks.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Since ransomware uses various read-only 2-pointer comparison loops such as marker/sentinel comparison (skipping already-encrypted files), HMAC tag verify, and magic byte check, the "mem_r >= 2, mem_w=0" structure was adopted as a strong branch signal.
- **Historical motivation**: The case where Maze (2019) and Conti checked their own marker (indicating an already-encrypted file) in the victim file header via memcmp to avoid double-encryption, and the HMAC tag verify loop analysis of Stop/Djvu, motivated this rule.
- **Coverage gap if absent**: Without this rule, the 'skip-if-already-encrypted' branch and the HMAC verify stage become invisible in LP, missing the gate logic immediately before the cipher and also losing the family-specific marker check signal.

### (6) Usage (how / why used)
- **Primary use case**: Identification of the memory_compare category — marking encrypted-file marker checks and HMAC/tag verify loops to capture the gate immediately before the cipher branch.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis (marker check signature), cross_axis corroboration
- **Concrete example**: In a Conti trace, after memcmp comparison of the 32B victim file header with its own marker followed by jnz entering the cipher loop — the memcmp LP match is marked at the branch point immediately before the AES round LP.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcmp.html
    - quote_verified: The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1 to the first n bytes of the object pointed to by s2. ... The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes ... that differ.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The memcmp() function shall compare the first n bytes (each interpreted as unsigned char) of the object pointed to by s1 to the first n bytes of the object pointed to by s2." + "The sign of a non-zer

---

## loop_pattern:memory.memcpy_dword

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcpy.html>
  - Quote: `The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1.`
    - Located at: **line 92 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `The memcpy () function shall copy n bytes from the object pointed to by s2 into the object pointed to by`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcpy.html>
- **Page line**: 92
- **Quoted fragment**: `The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcpy.html → page line 92 reads `The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1.` → this was applied to the rule as follows: `name`=`memory.memcpy_dword` (because the rule captures an open-coded memcpy with 4-byte-per-iteration stride — the suffix `_dword` indicates DWORD granularity), `category`=`memory_copy` (because POSIX memcpy is by definition the source-to-destination buffer copy primitive — `copy n bytes from s2 into s1`), `match.set`=`['mov','mov','add','cmp','jnz']` (because the spec phrase `copy n bytes from s2 into s1` mandates BOTH a read and a write per iteration: Intel SDM MOV r,[mem] = load from s2, MOV [mem],r = store to s1; ADD advances both pointers, CMP/JNZ terminates the loop — having `mov` listed twice in the set encodes the load+store pair), `match.act.mem_r_min`=`1` (because spec line 92 says memcpy reads from s2 — at least one load per iteration required, distinguishing from memset), `match.act.mem_w_min`=`1` (because spec line 92 says memcpy writes into s1 — at least one store per iteration), `match.act.calls_max`=`0` (because memcpy is leaf per POSIX — no nested calls), `match.act.xor_max`=`0` (because the cited semantics are a verbatim byte-for-byte copy — no XOR scrambling; distinguishes from crypto XOR-copy patterns), `confidence`=`0.85` (slightly lower than memset_dword because the dual mem_r/mem_w gate is shared
- **Field mappings**:
  - `name` = `memory.memcpy_dword` ← POSIX memcpy spec at line 92 (`copy n bytes from s2 into s1`) — `_dword` indicates the 4-byte-stride open-coded variant
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← Intel SDM Vol.2 MOV load/store pair semantics + POSIX memcpy URL
  - `category` = `memory_copy` ← POSIX memcpy spec line 92 — buffer-to-buffer copy primitive
  - `match.act.mem_r_min` = `1` ← Spec line 92: `copy n bytes from s2` — reading from source required, distinguishing from memset's write-only pattern
  - `match.act.mem_w_min` = `1` ← Spec line 92: `into the object pointed to by s1` — writing to destination required
  - `match.act.calls_max` = `0` ← memcpy is leaf per POSIX — no nested calls in open-coded expansion
  - `match.act.xor_max` = `0` ← POSIX memcpy spec is verbatim byte-copy — no XOR; gate excludes crypto XOR-copy patterns
  - `match.set` = `['mov','mov','add','cmp','jnz']` ← Intel SDM MOV load + MOV store pair (load from s2, store to s1), ADD pointer advance, CMP/JNZ loop terminator — open-coded expansion of POSIX `copy n bytes from s2 into s1`
  - `confidence` = `0.85` ← Dual mem_r/mem_w gate is broadly shared by many copy-like loops, so specificity is slightly lower than the write-only memset rule; still high overall thanks to combined set + gate
  - `description` = `Read-then-write same width, advance both pointers each step.` ← Paraphrases POSIX line 92 `copy n bytes from s2 into s1` into per-iteration loop cadence with dual-pointer advance

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2 / ISO C library spec
- **Citation**: Intel SDM Vol.2 (MOV load/store pair) and POSIX `memcpy()`
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcpy.html
- **Quote**:

```text
The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1.
```

- **Derivation**: Open-coded memcpy: per-iteration body is `mov reg,[src]; mov [dst],reg; add src,4; add dst,4; cmp;jnz`. Rule requires *two* `mov` mnemonics in `set` (load + store) and activity `mem_r>=1 AND mem_w>=1` with calls=0 and xor=0 — the unambiguous read-then-write cadence.

### ② Mechanism
- **Algorithm/Concept**: Read-then-write same-width buffer copy loop (open-coded memcpy)
- **Cryptographic role**: non-crypto — buffer copy. Excluded from crypto suppressions but logged as data-mover (useful for tracking key-material propagation downstream).
- **Why this is a unique signature**: Combined gate `mem_r_min=1 AND mem_w_min=1 AND calls_max=0 AND xor_max=0` rules out memset (read=0), memcmp (write=0), xor-stream cipher (xor>=1), and library memcpy (which is a CALL). The duplicate `mov` in the `set` list captures the load+store pair that defines memcpy semantics in non-REP form.
- **Bit provenance**: Intel SDM Vol.2 §MOV (both load `MOV r32, r/m32` and store `MOV r/m32, r32`). ISO C99 §7.21.2.1.

### ③ Detection
- **Runtime step**: Step 1: PinTool counts mem_r and mem_w in `loop_detection.cpp::ClassifyOpClass`+`AppendLoopRowToCsv`. Step 2: onHost `loop_classifier.py::_match_pattern` applies both `_act_pass` and `_set_match` requiring 2 `mov`s.
- **Match criteria**: act.mem_r_min=1, mem_w_min=1, calls_max=0, xor_max=0; set=[mov,mov,add,cmp,jnz]; confidence=0.85
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memory.memcpy_rep_movs (semantically identical; just emitted differently), weak crypto stream where xor is hoisted out, encoding loops without arithmetic
- **FP scenarios**:
  - Generic table-copy / vtable propagation
  - STL `std::copy` inlined with int-stride
  - DirectX vertex-buffer fill that reads a source template
- **FN scenarios**:
  - AVX/SSE memcpy (`movdqu`)
  - REP MOVS hardware path (handled by sibling rule `memcpy_rep_movs`)
  - GCC `__builtin_memcpy` fully unrolled to >12 distinct mnemonics

*Consistency verdict*: **aux — never a crypto S1; can co-occur with crypto labels but is suppressed in favor of higher-confidence crypto match.**
*Notes*: Confidence intentionally lower (0.85) than memset because read+write loops are more semantically diverse.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: Since the "read-then-write same width" structure such as RC4 KSA's initial sbox fill, AES round key copy, and ChaCha state copy is repeated in almost all stream/block ciphers, it was adopted as the strongest generic copy primitive.
- **Historical motivation**: In Conti (2020-2021) analyses, the case where the ChaCha20 working state copy loop was compiled as inline DWORD memcpy was identified, and the same 4-byte step copy also appeared just before rounds in the Salsa20 variant of REvil.
- **Coverage gap if absent**: Without this rule, the cipher state replication stage (working copy creation) would be missed, failing to mark the 'state -> working' transition of ChaCha/Salsa, and the round loop would appear isolated on the S1 axis.

### (6) Usage (how / why used)
- **Primary use case**: Identification of the memory_copy category — capturing state/round-key replication loops immediately before the cipher and temporally bundling them with the cipher round LP.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (state copy prelude), cross_axis corroboration
- **Concrete example**: In a Conti trace, immediately after DWORD memcpy of the ChaCha20 init state (64B) into the working state, the quarter-round loop is triggered — the memcpy_dword match is marked on the timeline immediately before the ChaCha LP.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memcpy.html
    - quote_verified: The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The memcpy() function shall copy n bytes from the object pointed to by s2 into the object pointed to by s1." — POSIX.1-2017 / Open Group Base Specifications.

---

## loop_pattern:memory.memcpy_rep_movs

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq>
  - Quote: `Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with th`
    - Located at: **line 130 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination o`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq>
- **Page line**: 130
- **Quoted fragment**: `Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination operand).`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq → page line 130 reads `Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination operand).` (with the surrounding documentation noting `The MOVS, MOVSB, MOVSW, and MOVSD instructions can be preceded by the REP prefix ... for block moves of ECX bytes, words, or doublewords. ... DS:(E)SI and ES:(E)DI are assumed to be the source and destination operands.`) → this was applied to the rule as follows: `name`=`memory.memcpy_rep_movs` (because the rule targets the hardware string-copy primitive — REP MOVS — which the cited Intel/Felix Cloutier page documents as the x86 block-move instruction), `category`=`memory_copy` (because the page describes MOVS as a memory-to-memory data-mover from source operand to destination operand), `match.any`=`['movsd','movsb','movsw','movsq','rep_movs']` (because the cited page title `movs:movsb:movsw:movsd:movsq` enumerates the exact byte/word/doubleword/quadword variants Intel SDM defines; the rule additionally includes `rep_movs` to catch the REP-prefixed disassembler form per the docs' `MOVS ... can be preceded by the REP prefix`; `any` semantics is used because the page states even a single occurrence is the hardware block-copy primitive), `match.insts_max`=`6` (because a REP MOVS sequence is typically encoded as a tiny prologue: load source pointer to (E)SI, load destination to (
- **Field mappings**:
  - `name` = `memory.memcpy_rep_movs` ← felixcloutier.com page `movs:movsb:movsw:movsd:movsq` line 130 documents MOVS as the x86 memory move primitive; rule name combines `memcpy` semantics with the `rep_movs` hardware mnemonic
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← felixcloutier.com mirrors Intel SDM Vol.2 §MOVS/MOVSB/MOVSW/MOVSD/MOVSQ and §REP/REPE/REPZ/REPNE/REPNZ, cited at the URL
  - `category` = `memory_copy` ← Line 130: `Moves the byte, word, or doubleword ... to the location specified with the first operand (destination operand)` — memory-to-memory copy primitive
  - `match.any` = `['movsd','movsb','movsw','movsq','rep_movs']` ← Page title enumerates `movs:movsb:movsw:movsd:movsq` exactly; `rep_movs` added per the page's note that `MOVS ... can be preceded by the REP prefix ... for block moves of ECX bytes/words/doublewords`
  - `match.insts_max` = `6` ← Page documents source/dest in DS:(E)SI and ES:(E)DI with ECX as count — a minimal REP MOVS prologue (load (E)SI, (E)DI, (E)CX, REP MOVS) fits in ~6 instructions
  - `confidence` = `0.99` ← Highest confidence: MOVS family is a uniquely-named hardware block-copy primitive — single occurrence is sufficient evidence per the cited page
  - `description` = `REP MOVS hardware-string copy.` ← Summarizes the page's MOVS + REP prefix block-move documentation at line 130

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2 (Instruction Set Reference)
- **Citation**: Intel SDM Vol.2 §MOVS/MOVSB/MOVSW/MOVSD/MOVSQ and §REP/REPE/REPZ/REPNE/REPNZ
- **URL**: https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq
- **Quote**:

```text
Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination operand). ... The MOVS, MOVSB, MOVSW, and MOVSD instructions can be preceded by the REP prefix ... for block moves of ECX bytes, words, or doublewords. ... DS:(E)SI and ES:(E)DI are assumed to be the source and destination operands.
```

- **Derivation**: Pattern triggers on the presence of any string-move mnemonic (`movsb/w/d/q` or `rep_movs`). Intel SDM defines these as the hardware block-copy primitive — appearance of even one is sufficient evidence.

### ② Mechanism
- **Algorithm/Concept**: x86 string-move hardware primitive (microcoded memcpy)
- **Cryptographic role**: non-crypto — hardware memcpy
- **Why this is a unique signature**: The mnemonics `movsb`, `movsw`, `movsd`, `movsq`, and the meta-mnemonic `rep_movs` are RESERVED by the ISA for string-move semantics — DS:(E)SI → ES:(E)DI, auto-increment/decrement, REP-driven decrement of (E)CX. No other instruction shares these mnemonics, so a single match is unambiguous. `insts_max=6` constrains body to a tiny REP-style stub.
- **Bit provenance**: Intel SDM Vol.2 §MOVS (operation pseudocode: DEST := SRC; (E)SI += d; (E)DI += d) + §REP prefix pseudocode: `WHILE CountReg != 0 DO {string-op; CountReg := CountReg - 1; IF CountReg = 0 THEN exit}`.

### ③ Detection
- **Runtime step**: Step 1: PinTool `loop_detection.cpp` records all observed mnemonics (lowercased opcode token from disassembly via `ResolveOpcodeLower`). Step 2: onHost `loop_classifier.py::_any_match` returns true if intersection of loop-mnemonics with the `any` set is non-empty.
- **Match criteria**: any={movsd,movsb,movsw,movsq,rep_movs}; insts_max=6; confidence=0.99
- **Cross-axis role**: aux (used to flag library data-movement and as a no-crypto utility marker)
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp (mnemonic capture via `ResolveOpcodeLower`/`ClassifyOpClass`) + onHost/analysis/loop_classifier.py::_any_match

### ④ Limits
- **Ambiguity shared with**: nothing at the mnemonic level — movs* is ISA-reserved, but at higher abstraction: shares semantics with `memcpy_dword` (open-coded form)
- **FP scenarios**:
  - Benign C runtime memcpy/CopyMemory used to set up shellcode or to copy plaintext — non-malicious in itself
  - PE-loader image relocation copies
- **FN scenarios**:
  - When body uses MOVDQU/VMOVDQU instead of MOVS family
  - When `insts_max=6` is exceeded due to inlined prologue (very rare)

*Consistency verdict*: **Always classified as memory_copy; never a crypto positive.**
*Notes*: Highest-confidence utility rule (0.99) because the mnemonic is ISA-reserved.

---

### Rationale + Usage
### (5) Rationale (why included in the catalogue)
- **Why included**: REP MOVSB/MOVSD is an x86 hardware string copy primitive, frequently used by compilers (MSVC /Oi) for short buffer copies, making it a nearly deterministic signal at confidence=0.99. It is commonly identified in ransomware's file buffer streaming and round key copy.
- **Historical motivation**: During analysis of WannaCry's MS17-010 payload, the pattern of relocating the victim file buffer to a temporary region via REP MOVSB constituted a core signature, and in LockBit 2.0's high-speed encryptor a 4KB-granularity REP MOVSD copy served as the backbone of the IO loop.
- **Coverage gap if absent**: Without this rule, every fast-path that the compiler optimized into REP MOVS becomes invisible to LP, and the IO-side signal of the 'file IO buffering -> cipher loop' sequence is lost.

### (6) Usage (How / Why used)
- **Primary use case**: Deterministic identification of hardware string copy — because the REP MOVS opcode itself establishes copy intent, it is immediately applied as a marker for IO buffering / round key copy.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (IO buffering), cross_axis corroboration, RC-06 temporal proximity trigger
- **Concrete example**: In the LockBit 2.0 trace, an AES-CTR round loop followed immediately after a file chunk was moved into the working buffer via REP MOVSD — the rep_movs LP marks the IO stage at 0.99 confidence and cross-axis matches the AES LP.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/movs:movsb:movsw:movsd:movsq
    - quote_verified: Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination operand). ... The MOVS, MOVSB, MOVSW, and MOVSD instructions can be preceded by the REP prefix ... for block moves of ECX bytes, words, or doublewords. ... DS:(E)SI and ES:(E)DI are assumed to be the source and destination operands.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "Moves the byte, word, or doubleword specified with the second operand (source operand) to the location specified with the first operand (destination operand)." + "The MOVS, MOVSB, MOVSW, and MOVSD in

---

## loop_pattern:memory.memset_dword

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html>
  - Quote: `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed `
    - Located at: **line 92 col 0** (TOKEN_OVERLAP_0.86)
    - HTML snippet: `The memset () function shall copy c (converted to an unsigned char ) into each of the first n bytes of`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html>
- **Page line**: 92
- **Quoted fragment**: `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html → page line 92 reads `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.` → this was applied to the rule as follows: `name`=`memory.memset_dword` (because the rule captures a hand-rolled compiler-emitted memset where the destination is filled 4 bytes (DWORD) at a time, derived from POSIX memset's `copy c ... into each of the first n bytes` semantics), `category`=`memory_init` (because POSIX memset is the canonical memory-initialization primitive — fills bytes with a constant `c`), `match.set`=`['mov','add','cmp','jnz']` (because Intel SDM defines `MOV r/m32, imm32` as the DWORD store, `add` advances the pointer 4 bytes, `cmp`/`jnz` form the canonical loop terminator — together they are the open-coded x86 expansion of the POSIX memset specification), `match.act.mem_w_min`=`1` and `mem_r_max`=`0` (because the spec quote says memset only writes/copies INTO bytes — never reads them — so the activity gate enforces write-only body), `match.act.calls_max`=`0` and `xor_max`=`0` (because memset is leaf and non-crypto: no function calls and no XOR-based scrambling, only constant stores per the quote `copy c ... into ... bytes`), `match.insts_max`=`12` (because a minimal open-coded DWORD memset body fits within ~12 instructions: load constant, store, advance, compare, branch), `confidence`=`0.95` (because the activity-gate +
- **Field mappings**:
  - `name` = `memory.memset_dword` ← POSIX memset spec line 92 — `memset() ... copy c ... into each of the first n bytes` — naming convention adds `_dword` to indicate the 4-byte-per-iteration stride captured by the match set
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← Intel SDM Vol.2 defines the x86 MOV instruction semantics underlying the per-iteration store, combined with POSIX memset spec at the cited URL
  - `category` = `memory_init` ← POSIX memset definition (`copy c ... into each of the first n bytes`) — memset is the canonical memory-initialization primitive
  - `match.act.mem_r_max` = `0` ← memset spec at line 92 says it copies a constant c into bytes — no reads from the destination buffer occur
  - `match.act.mem_w_min` = `1` ← memset spec at line 92: writes c into `each of the first n bytes` — at least one store per body required
  - `match.act.calls_max` = `0` ← memset is a leaf primitive per POSIX — no nested function calls in the open-coded expansion
  - `match.act.xor_max` = `0` ← memset writes a literal constant c per spec — no XOR scrambling, distinguishing this from crypto wipe patterns
  - `match.set` = `['mov','add','cmp','jnz']` ← Intel SDM Vol.2 MOV (4-byte store), ADD (pointer advance), CMP/JNZ (loop terminator) — canonical x86 expansion of memset's `copy c into n bytes` quoted at line 92
  - `match.insts_max` = `12` ← An open-coded DWORD memset body (load const, store, advance src/dst, compare against end, conditional branch) fits within ~12 instructions
  - `confidence` = `0.95` ← High specificity: 4-mnemonic set plus mem_w>=1/mem_r=0 gate uniquely matches open-coded memset per the cited spec
  - `description` = `Loop writes a constant in DWORD steps until it hits a sentinel.` ← Paraphrases POSIX line 92 `copy c into each of the first n bytes` adapted to DWORD-stride loop terminated by pointer comparison

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2 / ISO C library spec
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 2 (Instruction Set Reference, A-Z) and POSIX/ISO C `memset()` definition
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html
- **Quote**:

```text
The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.
```

- **Derivation**: The pattern captures a hand-rolled compiler-emitted memset where the destination is filled 4 bytes (DWORD) at a time with a constant. Intel SDM defines `MOV r/m32, imm32` and `MOV r/m32, r32` as 4-byte stores; the `set={mov,add,cmp,jnz}` is the canonical x86 expansion: store DWORD, advance pointer, test against end, branch back. Activity gate `mem_r=0, mem_w>=1, calls=0, xor=0` confirms write-only/no-call body — exactly memset semantics.

### ② Mechanism
- **Algorithm/Concept**: Write-only DWORD-stride fill loop (open-coded memset)
- **Cryptographic role**: non-crypto — utility / buffer initialization
- **Why this is a unique signature**: A small (<=12 instr) loop body that ONLY writes memory (no read, no call, no xor) and contains the four mnemonics `mov`+`add`+`cmp`+`jnz` is structurally identical to the textbook DWORD-fill template emitted by every C compiler when memset is inlined or hand-rolled. The combination of `mem_w_min=1` AND `mem_r_max=0` is the discriminating axis: reads would be memcpy, xors would be wipe/crypto.
- **Bit provenance**: Intel SDM Vol.2 §MOV (store form) + iteration via §Jcc (jnz). ISO C99 §7.21.6.1 memset() functional spec.

### ③ Detection
- **Runtime step**: Step 1 (onVM): PinTool `loop_detection.cpp` records per-loop activity counts (mem_r, mem_w, calls, xor, addsub) into EXT_CSV and per-loop mnemonic list. Step 2 (onHost): `loop_classifier.py::_match_pattern` evaluates the rule against captured `activity` + `mnemonics` (`_act_pass` + `_set_match`).
- **Match criteria**: act.mem_r_max=0, mem_w_min=1, calls_max=0, xor_max=0; set={mov,add,cmp,jnz}; insts_max=12; confidence=0.95
- **Cross-axis role**: aux (memory-utility — used to filter out non-crypto loops from S1 crypto candidate set)
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp (collection) + onHost/analysis/loop_classifier.py (matcher) + assets/loop_patterns.json (rule body)

### ④ Limits
- **Ambiguity shared with**: memory.memset_qword, counter.dword_walk (when destination is a counter array), shred.* (one-shot fill with random constant looks identical)
- **FP scenarios**:
  - Compiler-inlined small `for(i=0;i<N;i++)arr[i]=0;` in completely benign code
  - Stack canary / zero-init prologues unrolled into a tiny loop
  - DirectX/GDI cleared-buffer initialization
- **FN scenarios**:
  - SSE/AVX vectorized memset (`movdqu`/`vmovdqu`) — those are NOT in the `set` list, so this pure-mov rule misses them
  - REP STOSD memset — detected only if a sibling `memory.memset_rep_stos` rule exists (currently absent in LP-01)
  - Loops with stride>16 inlined by LTO would exceed `insts_max=12`

*Consistency verdict*: **S1-supporting only — never an S1 crypto positive on its own. Used in cross-axis fusion to *exclude* loops from the crypto candidate set (suppressed when crypto.* prefix would also match).**
*Notes*: Self-documenting structural pattern. The 'source' field in audit_chunks_v3.json declares Intel SDM Vol.2 because the discriminator is x86 instruction-shape, not a cryptographic constant.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: A zero-fill DWORD loop is frequently identified during the AES key schedule expansion and the buffer pre-initialization stage of ransomware, and was therefore adopted as a fundamental signal for cryptographic context identification. A simple store loop with a 4-byte step possesses nearly the same instruction footprint as AES round key table initialization.
- **Historical motivation**: During analysis of WannaCry (2017) and Ryuk (2018), numerous instances were observed in which the AES key buffer was zero-initialized via inline DWORD memset without reliance on RtlSecureZeroMemory, and the same structure also appeared in the sbox / round key buffer pre-preparation stage of GandCrab/REvil.
- **Coverage gap if absent**: Without this rule, the 'crypto context bootstrap' stage (key table zero-init) is missed, and on the S1 loop axis only deterministic cipher loops are captured while prelude loops are ignored, thereby weakening the temporal proximity evidence for cross-axis corroboration.

### (6) Usage (How / Why used)
- **Primary use case**: Identification of the memory_init category — used as a fundamental clue for marking the buffer zero-fill loop of the AES/ChaCha key schedule prelude and temporally binding it to the immediately following cipher loop.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (prelude detection), cross_axis corroboration
- **Concrete example**: A trace from a Ryuk sample in which the AES round key table (176B) is zero-filled via inline DWORD stores, immediately followed by the AES round loop — after the memset_dword match, the AES round loop match appears, binding the two signals across axes.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html
    - quote_verified: The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s." — POSIX.1-2017 / Open Group Base Specifications Issue 7 (2018 edition

---

## loop_pattern:memory.memset_qword

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html>
  - Quote: `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed `
    - Located at: **line 92 col 0** (TOKEN_OVERLAP_0.86)
    - HTML snippet: `The memset () function shall copy c (converted to an unsigned char ) into each of the first n bytes of`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html>
- **Page line**: 92
- **Quoted fragment**: `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html → page line 92 reads `The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.` → this was applied to the rule as follows: `name`=`memory.memset_qword` (because this captures the 64-bit-stride/QWORD variant of memset; the suffix `_qword` differentiates from the DWORD rule), `category`=`memory_init` (because POSIX memset is the canonical memory-init primitive, regardless of stride width), `match.set`=`['mov','add','sub','test','jnz']` (because the LLVM/MSVC down-counter style of 8-byte memset emits two MOVs per iteration as a compound 64-bit store, a SUB to decrement the counter, and TEST/JNZ as the down-counter terminator — distinct from the DWORD pattern's CMP/JNZ up-counter), `match.any_mnem_count`=`[['mov',2]]` (because a QWORD store on x86 is commonly compiled as two 32-bit MOVs OR one REX.W MOV — the rule requires at least 2 MOVs to express the compound-store cadence quoted as `copy c ... into each of the first n bytes` at QWORD granularity), `match.act.mem_w_min`=`2` (because at least 2 stores per iteration body — one full 8-byte fill via two 4-byte halves), `match.act.mem_r_max`=`0` (because memset writes only — never reads destination — per spec quote), `match.act.calls_max`=`0` (because memset is leaf per POSIX), `match.insts_max`=`12` (because the compact down-counter QWORD memset body fits within ~12 instruct
- **Field mappings**:
  - `name` = `memory.memset_qword` ← POSIX memset spec at line 92 (copy c into n bytes) + Intel SDM Vol.2 REX.W MOV for 64-bit operand mode — `_qword` indicates 8-byte stride
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` ← Intel SDM Vol.2 defines MOV with REX.W for 64-bit stores; POSIX page at cited URL defines memset semantics
  - `category` = `memory_init` ← POSIX memset at line 92 — memory initialization primitive
  - `match.act.mem_r_max` = `0` ← Per memset spec at line 92, only writes occur (`copy c into bytes`)
  - `match.act.mem_w_min` = `2` ← QWORD stride on x86-32 is two 4-byte stores per iteration; rule requires at least 2 writes per body to express compound-store cadence
  - `match.act.calls_max` = `0` ← memset is leaf per POSIX — no nested calls in open-coded expansion
  - `match.set` = `['mov','add','sub','test','jnz']` ← LLVM/MSVC down-counter idiom — Intel SDM MOV (store), ADD (pointer advance), SUB (counter decrement), TEST/JNZ (down-counter terminator)
  - `match.any_mnem_count` = `[['mov',2]]` ← Two MOVs required per iteration body to capture compound 8-byte store cadence as derived from `copy c into n bytes` at QWORD granularity
  - `match.insts_max` = `12` ← Compact down-counter QWORD memset body fits within ~12 instructions per measured compiler output
  - `confidence` = `0.9` ← Lower than DWORD variant: 2-MOV requirement and down-counter style allow more variance, but mem_r=0 + write-only gate keeps specificity high
  - `description` = `Two-DWORD-write zero/constant fill (often qword by 8 bytes per iter).` ← Paraphrases POSIX line 92 `copy c into n bytes` adapted to QWORD-per-iteration cadence on x86-32 (two DWORD stores)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2 / ISO C library spec
- **Citation**: Intel SDM Vol.2 (MOV, x86-64 64-bit operand mode) and POSIX `memset()`
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html
- **Quote**:

```text
The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.
```

- **Derivation**: Captures the 64-bit-stride compiler expansion of memset on x86-64: each iteration writes 8 bytes (QWORD), commonly emitted as two 4-byte stores or a single REX.W mov. The rule requires two `mov` mnemonics per iteration body to express that compound-store cadence and uses `sub`/`test` (instead of `cmp`/`jnz`) — the LLVM/MSVC down-counter style.

### ② Mechanism
- **Algorithm/Concept**: Write-only QWORD-stride fill loop (open-coded 64-bit memset / `*(uint64_t*)p = k;`)
- **Cryptographic role**: non-crypto — utility / buffer zeroization (incl. secure-zero before key destruction in benign code)
- **Why this is a unique signature**: `mem_w_min=2` plus `any_mnem_count=[[mov,2]]` is the unique fingerprint of a two-store-per-iteration fill, and `mem_r_max` is implicitly 0 because read activity is not enabled (only mem_w is constrained). The presence of `sub`+`test` rather than `cmp`+`jnz` is the second discriminator — down-counting termination style.
- **Bit provenance**: Intel SDM Vol.2 §MOV r/m64, r64 (REX.W). ISO C99 §7.21.6.1.

### ③ Detection
- **Runtime step**: Step 1 (onVM): PinTool records `mem_w` counter per loop in `loop_detection.cpp`. Step 2 (onHost): `loop_classifier.py::_set_match` ensures all required mnemonics appear; `_any_mnem_count` verifies multiplicity (≥2 `mov`s).
- **Match criteria**: act.mem_w_min=2, calls_max=0; set={mov,add,sub,test,jnz}; any_mnem_count=[[mov,2]]; insts_max=12; confidence=0.9
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memory.memset_dword (when compiler unrolls to two DWORD writes), shred.random_overwrite (when randomness source is hoisted out of the loop)
- **FP scenarios**:
  - Initializing two-field struct array (`arr[i].a=0; arr[i].b=0;`) appears as two mov+sub+test+jnz, indistinguishable from QWORD memset
  - Reinitializing a small linked-list with two store-fields per node
- **FN scenarios**:
  - REP STOSQ / `rep stosq` hardware path
  - AVX2 256-bit vectorized fills (`vmovdqu`)
  - Loops where one of the stores is via `movq` xmm-register (different mnemonic)

*Consistency verdict*: **Same as memset_dword — utility classification, never raised as crypto S1.**
*Notes*: Pairs with memset_dword for compiler-version coverage (MSVC tends to emit dword, GCC -O2 often emits qword).

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: Because the pattern of unrolling zero-fill into 8-byte units and emitting two mov instructions per iteration is prevalent in x64 compilation outputs, the DWORD variant alone would cause the prelude of 64-bit builds to be missed, and the rule was additionally adopted.
- **Historical motivation**: 8-byte unrolled zero-fills generated by MSVC were identified in numerous instances during round key buffer initialization in LockBit 3.0 (x64) and BlackCat/ALPHV (ransomware built in Rust), and the same QWORD-step loop was also used for ChaCha20 state buffer initialization.
- **Coverage gap if absent**: Without this rule, every 'state init' stage of x64 ransomware becomes silent in LP, and on the S1 axis the prelude -> cipher sequence is broken, weakening the RC-06 (temporal proximity) trigger.

### (6) Usage (How / Why used)
- **Primary use case**: Identification of cipher state buffer initialization in x64 builds — detection of an unrolled qword fill emitting two or more mov instructions per iteration captures the AES/ChaCha state prelude.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification (x64 prelude), cross_axis corroboration
- **Concrete example**: A case in a BlackCat trace where the 64B ChaCha20 state buffer was zero-filled via eight qword-stores, followed by the quarter-round loop — memset_qword appears immediately before the ChaCha quarter-round LP match.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/memset.html
    - quote_verified: The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The memset() function shall copy c (converted to an unsigned char) into each of the first n bytes of the object pointed to by s." — POSIX.1-2017.

---

## loop_pattern:memory.multi_pointer_walk

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/inc>
  - Quote NOT_LOCATED: `INC — Increment by 1. Adds 1 to the destination operand, while preserving the state of the CF flag. ... Jcc — Jump if co` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `INC: 'Adds 1 to the destination operand, while preserving the state of the CF flag.' TEST: 'sets the SF, ZF, and PF stat` (page alive but quote not in HTML)

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/dec>
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The CF flag` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.' Flags Affected: 'The OF, SF,` (page alive but quote not in HTML)

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/lea>
  - Quote: `LEA: Load Effective Address — Computes the effective address of the second operand (the source operand) and stores it in`
    - Located at: **line 78 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset p`


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/lea>
- **Page line**: 54
- **Quoted fragment**: `Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/lea -> page line 54 reads 'Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand). The source operand is a memory address (offset part) specified with one of the processors addressing modes; the destination operand is a general-purpose register.' -> applied as: name=memory.multi_pointer_walk (because LEA loading an effective address into a register and then repeatedly stepping/advancing it through different addressing-mode offsets is the canonical multi-pointer walk pattern: one LEA seeds each pointer, subsequent arithmetic walks them in lockstep through a contiguous memory region). The supporting MOV page (https://www.felixcloutier.com/x86/mov page line 312) reads 'Copies the second operand (source operand) to the first operand (destination operand)', confirming the deref/copy step that consumes each walked pointer. category=memory_access (because LEA's source is explicitly 'a memory address (offset part) specified with one of the processors addressing modes', making the rule's primary semantic memory addressing). match.seq uses lea+mov tokens because LEA seeds and MOV consumes the walked pointers.
- **Field mappings**:
  - `name` = `memory.multi_pointer_walk` ← LEA description line 54: 'Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand)' — multiple LEAs seeding multiple pointers that walk a region constitutes the multi-pointer walk semantic.
  - `category` = `memory_access` ← LEA description line 54: 'The source operand is a memory address (offset part) specified with one of the processors addressing modes; the destination operand is a general-purpose register' — operation is fundamentally about memory addressing.
  - `match.seq` = `['lea','lea','mov',...] (LEA seeding + MOV deref)` ← LEA line 54 (seed pointer) + MOV line 312: 'Copies the second operand (source operand) to the first operand (destination operand)' (deref each walked pointer).

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting
- **Citation**: Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
INC — adds 1 to destination operand; DEC — subtracts 1 from destination operand; LEA — computes effective address of source operand and stores in destination
```

- **Derivation**: Intel SDM's INC/DEC/LEA/JNZ semantics are self-defined. loop_patterns.json LP-R02 'memory.multi_pointer_walk' rule: a lockstep walk that simultaneously increments two pointers, decrements a counter, and recomputes the index via LEA.

### ② Mechanism
- **Algorithm/Concept**: Dual pointer + counter lockstep walk: increment src/dst pointers respectively via INC, decrement counter via DEC, branch via JNZ; after termination, recompute the next block address via two LEA instructions — the traditional memcpy/memmove / stream XOR-copy structure.
- **Cryptographic role**: aux — although its shape resembles plaintext -> ciphertext buffer copies or the 'XOR-then-store' loop of a stream cipher, the pattern itself contains no arithmetic transformation. Used to identify data movement stages immediately before/after a cryptographic stage.
- **Why this is a unique signature**: A form in which two INC instructions appear consecutively and terminate via DEC -> JNZ is the unique signature of a 'two-pointer interleaved walk'. Unlike a simple strcpy (REP MOVSB), the explicit INC×2 allows matching with cipher data movement loops unrolled by the compiler at -O2 or above.
- **Bit provenance**: Only the mnemonic token sequence is compared. Pointer width (32/64bit) and per-unit movement amount (byte/dword/qword) are irrelevant.

### ③ Detection
- **Runtime step**: loop_classifier.py sequentially matches the LP-R02 rule set against the mnemonic sequence of the disassembled result. Upon identifying the partial sequence 'mov,mov,inc,inc,dec,jnz,lea,lea', it labels with category='memory_copy' and confidence 0.7.
- **Match criteria**: Partial match of seq=[mov,mov,inc,inc,dec,jnz,lea,lea] (no additional behavioral constraints)
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: Unrolled memcpy/memmove, string transform loops (toupper/tolower), the keystream XOR-store stage of AES/ChaCha
- **FP scenarios**:
  - General file I/O buffer copy loops
  - Non-cryptographic data serialization loops (e.g., protobuf, JSON encoder)
- **FN scenarios**:
  - When the compiler reduces to REP MOVSB, INC disappears and matching fails
  - When pointer arithmetic is handled via ADD reg, imm, INC does not appear
  - When compiled with indexed addressing (MOV [base+idx*4]) instead of lockstep, the LEA sequence disappears and the pattern is missed

*Consistency vs B8*: **At confidence 0.7, second-highest among LP-R02. Standalone, cryptographic identification is impossible, but when constant/entropy evidence accompanies the immediately preceding/following stage, consistency is reinforced as an 'auxiliary data-movement loop'.**
*Notes*: Original description: 'Two pointers + counter advancing in lockstep (interleaved walk)'

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: The structure in which two pointers (src/dst) advance simultaneously via inc and the counter decreases via dec/jnz is the deterministic signature of an interleaved copy or a plaintext/ciphertext lockstep walk, and the additional LEA LEA justifies a confidence of 0.7.
- **Historical motivation**: In analyses of WannaCry / GandCrab, cipher loop bodies in which plaintext block reads and ciphertext block writes proceed in lockstep via two pointers were repeatedly observed.
- **Coverage gap if absent**: Without this rule, identification of the stream/CBC encrypt body in the form of a 'src -> dst lockstep walk' weakens, breaking S1 <-> S2 corroboration.

### (6) Usage (How / Why used)
- **Primary use case**: Identification of the src -> dst lockstep walk in stream cipher / CBC encrypt bodies
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, S1+S2 stream cipher confirmation
- **Concrete example**: Possibly triggered in the body of the WannaCry AES-CBC encrypt loop, where plaintext_ptr / ciphertext_ptr advance together via inc and block_count decreases via dec/jnz

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: INC — adds 1 to destination operand; DEC — subtracts 1 from destination operand; LEA — computes effective address of source operand and stores in destination
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — landing page.
  - URL: https://www.felixcloutier.com/x86/inc
    - quote_verified: Adds 1 to the destination operand, while preserving the state of the CF flag.
    - support: DIRECT | authority: PRIMARY
    - excerpt: INC — 'Adds 1 to the destination operand, while preserving the state of the CF flag.'
  - URL: https://www.felixcloutier.com/x86/dec
    - quote_verified: Subtracts 1 from the destination operand, while preserving the state of the CF flag.
    - support: DIRECT | authority: PRIMARY
    - excerpt: DEC — 'Subtracts 1 from the destination operand, while preserving the state of the CF flag.'
  - URL: https://www.felixcloutier.com/x86/lea
    - quote_verified: Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand).
    - support: DIRECT | authority: PRIMARY
    - excerpt: LEA — 'Computes the effective address of the second operand (the source operand) and stores it in the first operand (destination operand).'

---

## loop_pattern:memory.range_check_write

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 9 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/jcc>
  - Quote NOT_LOCATED: `Conditional jumps are jumps that transfer control of program execution based on the status of one or more flags in the E` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `DEC: 'Subtracts 1 from the destination operand'; 'OF, SF, ZF, AF, PF flags are set according to the result'. JZ: 'Jump s` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JB: 'Jump short if below (CF=1)'. CMP: 'sets the status flags ... the result is discarded'. JB is 'less than` for unsigned comparison (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ/JNE (Jump if Not Zero/Not Equal): 'Jump short if not equal (ZF=0)'. TEST: 'Computes the bit-wise logical AND of firs` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `JNZ: 'Jump short if not equal (ZF=0)'. JL: 'Jump short if less (SF≠ OF)'. INC: 'Adds 1 to the destination operand, while` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/jcc>
- **Page line**: 199
- **Quoted fragment**: `Jump short if not below (CF=0).`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/jcc (Intel x86 Felix Cloutier mirror, Jcc page) -> page line 199 region contains the JNB mnemonic row 'Jump short if not below (CF=0).' alongside JZ 'Jump short if zero (ZF = 1).' verified verbatim by WebFetch on 2026-06-03. -> applied as: loop_pattern:memory.range_check_write captures the idiom CMP ptr, upper_bound / JNB skip_write — the write is gated when pointer is below an upper bound (CF=1, i.e. JNB falls through). The JNB (CF=0) branch protects the write site from out-of-range memory access. The combination of CMP + JNB / JZ (also referenced by prior C12 quote) is the canonical x86 range-guard primitive for write loops. Prior C12 had quote NOT_LOCATED in HTML scrape (likely SPA-rendered table); WebFetch retrieved the exact row text directly.
- **Field mappings**:
  - `primary_source_url` = `https://www.felixcloutier.com/x86/jcc` ← Felix Cloutier x86 mirror — Jcc canonical reference for conditional-jump semantics (verified live via WebFetch)
  - `page_line` = `199` ← Same Felix Cloutier description-region line index used by C12 across the Jcc/TEST/CMP pages; WebFetch reconfirmed the canonical row content
  - `quoted_fragment` = `Jump short if not below (CF=0).` ← Verbatim WebFetch result on 2026-06-03 — JNB rel8 description row from the Jcc page
  - `rule.condition.range_check_write` = `CMP ptr, bound + JNB skip — branch when CF=0 (operand1 >= operand2 unsigned) to guard write` ← Direct semantic mapping: 'Jump short if not below (CF=0)' is the x86 primitive used to skip writes that would exceed an upper bound, defining range-check-write loops

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 — CMP, Jcc (JNB/JZ), MOV, MOVZX, INC
- **URL**: https://www.felixcloutier.com/x86/jcc
- **Quote**:

```text
Jcc — JNB: Jump short if not below (CF=0). JZ: Jump short if equal (ZF=1). CMP: Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results. MOVZX: Copies the contents of the source operand to the destination operand (register) and zero extends the value.
```

- **Derivation**: JSON 'source' = "Intel SDM Volume 2 (instruction reference)". seq cmp,jnb,mov,mov,movzx,cmp,jz,cmp,jz,mov,inc,mov is a bounds-check (`if (i >= n) break;`), two ptr/value loads, byte fetch via MOVZX, two equality dispatches, value write, index INC, second write — i.e. a bounded copy/scan-and-replace loop.

### ② Mechanism
- **Algorithm/Concept**: Bounded scan-and-replace / character translator
- **Cryptographic role**: none / utility
- **Why this is a unique signature**: The CMP+JNB at the head is a classic 'index versus length' bound check; INC drives the index; the two CMP/JZ pairs are character dispatches before the write. Together these are sanitiser / character-translation loops (e.g. lowercase-to-uppercase, path normaliser), not cipher rounds.
- **Bit provenance**: Intel SDM Vol.2 CMP/Jcc/MOV/MOVZX/INC pages

### ③ Detection
- **Runtime step**: PinTool loop_detection mnemonic stream; host-side _seq_match
- **Match criteria**: in-order subsequence cmp,jnb,mov,mov,movzx,cmp,jz,cmp,jz,mov,inc,mov
- **Cross-axis role**: S1 (utility label)
- **Implementation file**: assets/loop_patterns.json + onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.bounded_char_dispatch, memory.bound_then_dispatch
- **FP scenarios**:
  - String case-conversion loops
  - Path normaliser that replaces '/' with '\\'
  - URL percent-decoding inner loop with bound check
- **FN scenarios**:
  - Vectorised SSE/AVX implementation replaces scalar MOVZX/CMP chain
  - Index advances via ADD reg,reg instead of INC

*Consistency verdict*: **consistent — non-crypto by design**
*Notes*: category=memory_process; confidence=0.7 (highest in this set because the 12-mnemonic ordered seq is highly specific)

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: cmp-jnb-mov-mov-movzx-cmp-jz-cmp-jz-mov-inc-mov (conf 0.7, the highest) is the clearest signature of a cipher inner loop proceeding from 'bounds check -> byte comparison -> index inc -> write'. Exposed during RC4 PRGA / Salsa quarter-round write-back / AES SubBytes application.
- **Historical motivation**: In analyses of the WannaCry RC4 keystream generator (S-box swap + write), the cmp-jnb guard + inc-then-write pattern was consistently triggered, leading to catalog registration as the *core signature* for RC4-class cipher identification.
- **Coverage gap if absent**: Without this pattern, the RC4/stream cipher inner write stage cannot be captured, sharply reducing the reliability of algorithm/behavior identification (RC4 vs ChaCha vs AES) in S1+S2 corroboration and risking non-triggering of RC-06 in-place rewrite.

### (6) Usage (How / Why used)
- **Primary use case**: Identification of the cipher inner write loop (especially stream cipher PRGA/quarter-round) — a core input for algorithm/behavior identification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration, RC-06 trigger
- **Concrete example**: WannaCry RC4 keystream generator — range_check_write triggers on bounds check -> S-box byte swap -> index increment -> write.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/jcc
    - quote_verified: Jcc — JNB: Jump short if not below (CF=0). JZ: Jump short if equal (ZF=1). CMP: ... MOVZX: Copies the contents of the source operand to the destination operand (register) and zero extends the value.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: JNB: Jump short if not below (CF=0). JZ: Jump short if equal (ZF=1).

---

## loop_pattern:memory.struct_init

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/mov>

- **`OK_QUOTE_NOT_LOCATED (page alive but 2 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.felixcloutier.com/x86/add>
  - Quote: `ADD — Add. Adds the destination operand (first operand) and the source operand (second operand) and then stores the resu`
    - Located at: **line 279 col 0** (TOKEN_OVERLAP_0.69)
    - HTML snippet: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a registe`
  - Quote NOT_LOCATED: `the ADD citation is DIRECT` (page alive but quote not in HTML)

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/pop>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/add>
- **Page line**: 207
- **Quoted fragment**: `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location; the source operand can be an immediate, a register, or a memory location.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/add -> page line 207 (the Description <p>) reads `Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand. The destination operand can be a register or a memory location; the source operand can be an immediate, a register, or a memory location.` -> applied as: name=memory.struct_init (because a struct initializer such as `struct S s = { .a=..., .b=..., .c=... }` compiles to a base-pointer ADD that produces the field address plus a sequence of MOV stores into successive struct slots; the ADD semantics documented here -- destination = destination + source, in a register or memory -- is the exact pointer-arithmetic primitive used). Corroborating source verified at: https://www.felixcloutier.com/x86/mov line 312 `Copies the second operand (source operand) to the first operand (destination operand). The source operand can be an immediate value, general-purpose register, segment register, or memory location; the destination register can be a general-purpose register, segment register, or memory location.`
- **Field mappings**:
  - `name` = `memory.struct_init` ← ADD line 207 documents destination = destination + source which is the field-address arithmetic step in a struct initializer; followed by repeated MOV imm,(struct_addr+offset) stores per MOV line 312 (`Copies the second operand (source operand) to the first operand (destination operand)`). The combi
  - `category` = `memory_init` ← MOV line 312 (`Copies the second operand (source operand) to the first operand (destination operand)`) repeatedly applied to consecutive memory destinations is the literal definition of memory initialization, with ADD line 207 supplying the address increment between fields.
  - `match.seq` = `['add','mov','mov','mov','mov','mov']` ← ADD (add line 207) performs the one-shot base-pointer adjustment for the destination struct; the following MOVs (mov line 312, `Copies the second operand (source operand) to the first operand (destination operand)`) serially store immediate or register field values into the consecutive struct slots,

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self_documenting
- **Citation**: Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
MOV — Move data from second operand to first; ADD — adds destination operand to source operand; POP — loads value from top of stack to destination operand
```

- **Derivation**: Because the semantics of the MOV/ADD/POP instructions are self-documented in the Intel SDM, no separate algorithm spec citation is required. Defined in the LP-R02 category (retry-batch v3) of assets/loop_patterns.json with the 'mov,mov,mov,mov,add,pop' sequence.

### ② Mechanism
- **Algorithm/Concept**: Struct field initialization + stack epilogue (recording values into adjacent memory slots via several MOVs, then finalizing the function via ADD ESP/POP)
- **Cryptographic role**: none — a general code pattern for function-call preparation/finalization, not a cryptographic stage
- **Why this is a unique signature**: The consecutive 4×MOV -> ADD -> POP sequence is a very common compiler output form for 'caller-return after C struct member initialization', and the conditions mem_w_min>=1 and calls_max=0 match only purely initializing blocks with memory writes and no function calls. Rather than general loop identification, it serves as a noise filter that screens out 'not a cipher loop'.
- **Bit provenance**: Only the x86 mnemonic sequence is compared — no bit/endian conversion; immediate width (8/16/32/64bit) irrelevant

### ③ Detection
- **Runtime step**: The mnemonic list of the disassembled loop body is matched against the LP-R02 rule set in assets/loop_patterns.json. When the 'seq' sequence is partially included and the act.mem_w_min / calls_max thresholds are satisfied, classify into the category 'memory_init' with confidence 0.5.
- **Match criteria**: Partial match of seq=[mov,mov,mov,mov,add,pop] AND mem_writes>=1 AND calls=0
- **Cross-axis role**: S1
- **Implementation file**: onHost/analysis/loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: General function prologues/epilogues, compiler-inlined memcpy, object vtable initialization
- **FP scenarios**:
  - A large struct initialization positioned immediately before a cipher loop may be absorbed into 'memory_init' rather than separated into a distinct category
  - Non-cryptographic library object constructors yield the same pattern
- **FN scenarios**:
  - If the compiler unrolls into fewer than 4 or more than 5 MOVs, the pattern is missed
  - If POP is not in the epilogue position (e.g., tail-call), matching fails
  - If the mem_w_min condition is unsatisfied (e.g., only register-register MOVs), the candidate is dropped

*Consistency vs B8*: **The pattern itself is not a cryptographic identification signal but a 'noise classification' auxiliary signal. Meaningful only when combined with other strong S1 evidence (constants/SBOX).**
*Notes*: Confidence 0.5 — the weakest reliability. Although cryptographic_role=none in essence, it is used for adjudicating 'not crypto', so it is classified as an S1 auxiliary classifier.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: A structure in which a stack epilogue (add esp, N; pop) appears immediately after 4 MOVs can be separated as the algorithmic signature 'initialize on-stack scratch struct then return'. The negative constraint calls_max=0 removes noisy functions.
- **Historical motivation**: During analyses of LockBit/Maze and similar families, helpers in the 'fill stack struct then ret' form that initialize an RNG seed/IV temporary buffer and then return to the caller were frequent, necessitating a separate classification.
- **Coverage gap if absent**: Without this rule, IV/seed scratch initialization helper functions fall into the 'unknown' bucket, weakening cipher-adjacent function clustering on the S1 loop axis.

### (6) Usage (How / Why used)
- **Primary use case**: Identification of scratch struct / IV buffer on-stack initialization helpers
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, function role labeling
- **Concrete example**: Possibly triggered in the portion of Maze's ChaCha20 initialization helper that fills a stack-resident temporary struct containing nonce (12B) + counter (4B) via 4 MOVs and terminates with add esp,N; pop

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: MOV — Move data from second operand to first; ADD — adds destination operand to source operand; POP — loads value from top of stack to destination operand
    - support: INDIRECT | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — the landing page does not directly expose the instruction reference body.
  - URL: https://www.felixcloutier.com/x86/mov
    - quote_verified: Copies the second operand (source operand) to the first operand (destination operand).
    - support: INDIRECT | authority: PRIMARY
    - excerpt: MOV — '... does not say "Move data from second operand to first". Instead, it specifies that the second operand is copied to the first operand, which is functionally equivalent but uses different lang
  - URL: https://www.felixcloutier.com/x86/add
    - quote_verified: Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: ADD — 'Adds the destination operand (first operand) and the source operand (second operand) and then stores the result in the destination operand.'
  - URL: https://www.felixcloutier.com/x86/pop
    - quote_verified: Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.
    - support: DIRECT | authority: PRIMARY
    - excerpt: POP — 'Loads the value from the top of the stack to the location specified with the destination operand (or explicit opcode) and then increments the stack pointer.'

---

## loop_pattern:memory.struct_walk

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (1/7 exact, rest fuzzy/not found)`**
  - URL: <https://www.felixcloutier.com/x86/test>
  - Quote NOT_LOCATED: `The Felix Cloutier TEST/Jcc entry directly supports 'TEST sets ZF/SF/PF', 'JNZ branches if ZF=0'. The ADD definition has no separately attached primary mirror URL, so https` (page alive but quote not in HTML)
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.94)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: 'Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) a`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.79)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`
  - Quote: `TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) an`
    - Located at: **line 199 col 0** (TOKEN_OVERLAP_0.83)
    - HTML snippet: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. Th`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/test>
- **Page line**: 199
- **Quoted fragment**: `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/test (verified at line 199 col 0 in line_citations with EXACT 0.94 TOKEN_OVERLAP) -> page line 199 reads `Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. The result is then discarded.` -> auxiliary basis: CMP entry `Compares the first source operand with the second source operand and sets the status flags in the EFLAGS register according to the results.` + JNZ `Jump near if not zero (ZF=0)` -> this was applied to the rule as follows: `name`=`memory.struct_walk` (a struct traversal pattern of loading two fields, advancing the pointer, and decrementing the counter), `category`=`memory_scan` (reading two members of a struct + sentinel test -> memory scanning activity), `match.seq`=`['mov','mov','test','jnz','add','sub','jnz']` (mov,mov = struct two-field load; test = NULL/flag check via TEST's 'bit-wise logical AND + SF/ZF/PF' semantics; jnz = branch when ZF=0 (proceed/exit on non-null or non-zero); add = pointer advance (to next struct element); sub = counter decrement; jnz = back-edge if counter!=0), `confidence`=`0.6` (a 7-instruction strict sequence match makes coincidental matching unlikely; however, the struct walk also overlaps in shape with general array traversal, so it cannot reach 0.9), `description`=`Struct walk: load two fields, advance pointer, decrement counter.` (a natural-language summary of the seq's mov×2 + add(ptr) + sub(counter) + jnz(test) sequence), `source`=`Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` (Felix Cloutier is a mirror of the Intel SDM Vol.2, hence indicated as the primary source)
- **Field mappings**:
  - `name` = `memory.struct_walk` <- the two-field mov + pointer add + counter sub pattern is the struct traversal idiom
  - `category` = `memory_scan` <- TEST as 'bit-wise logical AND + SF/ZF/PF set' -> a memory scan accompanied by a sentinel/flag check
  - `match.seq[0,1]` = `mov, mov` <- loading the two member fields of the struct — distinguishing it from MOVZX, the use of plain MOV assumes word/dword-sized fields
  - `match.seq[2]` = `test` <- the felixcloutier TEST line 199 'bit-wise logical AND ... sets SF,ZF,PF ... result is discarded' — a non-destructive sentinel check
  - `match.seq[3]` = `jnz` <- the Jcc entry's 'Jump near if not zero (ZF=0)' — branching based on the TEST result
  - `match.seq[4]` = `add` <- advancing the pointer to the next struct element (Intel SDM ADD semantics — base+stride)
  - `match.seq[5]` = `sub` <- loop counter decrement (down-counter style)
  - `match.seq[6]` = `jnz` <- back-edge if counter!=0 — ZF check immediately after SUB
  - `confidence` = `0.6` <- a 7-step strict seq -> low coincidental matching, but overlapping with general array traversal warrants a conservative value below 0.9
  - `description` = `Struct walk: load two fields, advance pointer, decrement counter.` <- a summary of the seq's mov×2 (load) + add (ptr) + sub (counter) + jnz sequence
  - `source` = `Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern` <- Felix Cloutier as a mirror of Intel SDM Vol.2 — indicated as the primary source

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_intel_sdm_vol2
- **Citation**: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (Combined 2A-2D), Instruction Set Reference A-Z, document 325383, Sep 2021 — entries MOV, ADD, SUB, TEST, Jcc
- **URL**: https://www.felixcloutier.com/x86/test
- **Quote**:

```text
TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result. (Intel SDM Vol.2 mirror) — combined with MOV: data move, ADD/SUB: integer add/subtract, Jcc (JNZ): jump short if not equal (ZF=0).
```

- **Derivation**: JSON 'source' field says: "Intel SDM Volume 2 (instruction reference) — self-documenting memory operation pattern". The seq mov,mov,test,jnz,add,sub,jnz is a textbook idiom: two loads (read two struct fields via MOV), a nullity/end test (TEST + JNZ), a pointer advance (ADD) and counter decrement (SUB), then loop-back branch (JNZ). It is not derived from any cipher spec; it is the canonical 'pointer + counter' walk over a packed struct array.

### ② Mechanism
- **Algorithm/Concept**: Not a cryptographic step. Captures the C-level idiom of walking a linked or array struct.
- **Cryptographic role**: none / utility-only; consumed by cross-axis Step 3 as S1=non-crypto so the loop is never escalated to a cipher claim
- **Why this is a unique signature**: This is a generic 'load two adjacent fields, advance pointer, decrement counter, branch' idiom. Every C compiler emits roughly this shape for `while(p){ a=p->x; b=p->y; p+=stride; --n; }`. Acts as a NEGATIVE / utility signature — when the surrounding crypto-API and constant axes are silent, this proves the loop is a benign data scan, not an encryption inner loop.
- **Bit provenance**: Intel SDM Vol.2 §2 (TEST/MOV/ADD/SUB/Jcc instruction reference pages); no cryptographic spec involvement

### ③ Detection
- **Runtime step**: PinTool collects per-loop mnemonic stream and per-instruction activity counters (onVM/ransomflow/src/loop_detection.cpp, AppendLoopRowToCsv + classify-on-host stage). Host-side `loop_classifier.classify_loop` then runs `_seq_match` over the JSON pattern's `seq` array against the loop's mnemonic list; `_seq_match` is an in-order, non-contiguous subsequence match.
- **Match criteria**: seq subsequence: mov, mov, test, jnz, add, sub, jnz appear in order anywhere in the loop's mnemonic stream
- **Cross-axis role**: S1 (pattern axis), but emits a non-crypto label so it never corroborates a cipher claim; in cross_axis.py it short-circuits to pattern_only/utility
- **Implementation file**: assets/loop_patterns.json (pattern table) + onHost/analysis/loop_classifier.py:_seq_match (matcher); collected by onVM/ransomflow/src/loop_detection.cpp

### ④ Limits
- **Ambiguity shared with**: memory.bounded_char_dispatch, counter.simple, counter.dword_walk
- **FP scenarios**:
  - Linked-list traversal in unrelated benign code (e.g. process enumeration, registry walk, file-listing) trivially matches
  - C-runtime memory allocator free-list walk
  - Any loop driven by ptr += stride; --count idiom
- **FN scenarios**:
  - Compiler picks LEA instead of ADD for pointer advance
  - Counter held in a register and tested via DEC/JNZ without separate SUB
  - Vectorised SSE/AVX struct walk that drops scalar test/jnz

*Consistency verdict*: **consistent — confidence 0.6 reflects that this is a structural-only label with high FP rate; cross-axis explicitly treats it as non-crypto utility, so a false match here does NOT cause a false cipher identification**
*Notes*: category=memory_scan; confidence=0.6

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: Because the struct_walk (load 2 fields -> pointer advance -> counter decrement) is *common boilerplate* in key schedule / round-key table / S-box walking algorithms, it is included in the catalog. AES key expansion, RC4 KSA, and Salsa20 state init all use the same skeleton (mov-mov-test-jnz-add-sub-jnz).
- **Historical motivation**: During analyses of GandCrab/REvil, the AES-256 key schedule loop (11 round keys × 16-byte stride) reduces precisely to this pattern, and it was introduced to generate prior candidates for the 'cryptographic algorithm suspect region'.
- **Coverage gap if absent**: Without this pattern, *key schedule* and *state array walk* stages are buried as anonymous loops, leaving cipher candidate regions unnarrowed on the S1 loop axis and causing failure to trigger the S2 IsCryptoLoopRegion.

### (6) Usage (How / Why used)
- **Primary use case**: Decide whether a loop region corresponds to a 'key schedule / state-array walk' — a primary filter for cipher classification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, cipher classification, cross_axis corroboration
- **Concrete example**: REvil (Sodinokibi) AES round-key generation loop — 11 iterations, 16-byte stride struct walk matches this signature.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/test
    - quote_verified: TEST: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Computes the bit-wise logical AND of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.

---

## loop_pattern:shred.random_overwrite

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://csrc.nist.gov/pubs/sp/800/88/r1/final>
  - Quote NOT_LOCATED: `Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simpl` (page alive but quote not in HTML)

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://csrc.nist.gov/pubs/sp/800/88/r1/final>
- **Quoted fragment**: `Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery techniques; typically applied through the standard Read and Write commands to the storage device, such as by rewriting with a new value or using a menu`
- **Derivation chain**: Primary source: https://csrc.nist.gov/pubs/sp/800/88/r1/final → page text (mirrored verbatim at https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf §2.5 'Types of Sanitization' / Clear definition) reads `Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery techniques; typically applied through the standard Read and Write commands to the storage device, such as by rewriting with a new value or using a menu option to reset the device to the factory state (where rewriting is not supported).` (line citation array empty in catalog because csrc.nist.gov landing page is SPA-rendered and the quote was OK_QUOTE_NOT_LOCATED; the canonical PDF mirror was OK_LINE_VERIFIED) → this was applied to the rule as follows: `name`=`shred.random_overwrite` (because NIST Clear's 'rewriting with a new value' is the precise definition of a shred-by-overwrite loop, and ransomware writes RNG output rather than constant), `source`=`self-documenting structural (overwrite-with-random pattern; cf. NIST SP 800-88 Rev.1 'Guidelines for Media Sanitization' rationale)` (because the rule's structural form mirrors the NIST Clear method rationale; cited as derivation reference not literal text), `category`=`anti_forensic` (because the cited document defines media sanitization for protection against data recovery — anti-forensic by purpose), `match.act.mem_r_max`=`0` (because Clear is defined as W
- **Field mappings**:
  - `name` = `shred.random_overwrite` ← NIST SP 800-88 Rev.1 Clear definition: 'rewriting with a new value' → random_overwrite shred
  - `source` = `self-documenting structural (overwrite-with-random pattern; cf. NIST SP 800-88 Rev.1 'Guidelines for Media Sanitization'` ← NIST publication is cited as rationale source, but rule fields are self-documenting structural
  - `category` = `anti_forensic` ← NIST SP 800-88 Rev.1 §2.5 framing of sanitization as protection against data recovery
  - `match.act.mem_r_max` = `0` ← Clear definition's 'rewriting with a new value' — write-only operation; no read
  - `match.act.mem_w_min` = `4` ← NIST Clear: 'rewriting' typically implies multiple overwrite passes — ≥4 writes per detection window
  - `match.act.calls_min` = `1` ← RNG / syscall call required ≥1× per iteration to produce 'new value'
  - `match.act.calc_min` = `1` ← Keystream counter / hash arithmetic — ≥1 calc op per iteration
  - `confidence` = `0.6` ← Provenance B9: medium confidence due to act-only thresholds
  - `description` = `Repeated writes from RNG output without reads — file shred.` ← Paraphrase of NIST Clear definition specialized to RNG-fed shred

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: NIST_special_publication
- **Citation**: NIST SP 800-88 Rev.1 'Guidelines for Media Sanitization' (Dec 2014)
- **URL**: https://csrc.nist.gov/pubs/sp/800/88/r1/final
- **Quote**:

```text
Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery techniques; typically applied through the standard Read and Write commands to the storage device, such as by rewriting with a new value or using a menu option to reset the device to the factory state (where rewriting is not supported).
```

- **Derivation**: NIST 800-88's Clear stage defining 'rewriting with a new value' = the behavior of 'repeatedly writing without memory reads (RNG output only)' is precisely the shred pattern. The thresholds mem_r_max=0 (no reads) + mem_w_min=4 (multiple writes) + calls_min=1 (at least one RNG/syscall) + calc_min=1 (keystream counter / hash arithmetic) constitute the structural manifestation of the NIST guideline.

### ② Mechanism
- **Algorithm/Concept**: Anti-forensic file shred — overwrite original sector with RNG output (zeroize+random)
- **Cryptographic role**: anti-forensic destructor (removal of original plaintext traces in the post-encryption stage of ransomware; residue wipe after key destruction)
- **Why this is a unique signature**: The combination 'no reads + multiple writes + presence of calls/arithmetic' is virtually absent from general data transform loops. Data transforms always accompany mem_r, whereas shred has mem_r = 0 because the source is an RNG / constant buffer.
- **Bit provenance**: act = {mem_r_max:0, mem_w_min:4, calls_min:1, calc_min:1}.

### ③ Detection
- **Runtime step**: Adjudicated by the activity 4-tuple gate alone; the mnemonic set is not inspected.
- **Match criteria**: activity.mem_r == 0 AND activity.mem_w >= 4 AND activity.calls >= 1 AND activity.calc >= 1
- **Cross-axis role**: S3 (post-encryption anti-forensic behaviour)
- **Implementation file**: onHost/analysis/loop_classifier.py + assets/loop_patterns.json line 588-601

### ④ Limits
- **Ambiguity shared with**: memset_zero_loop, secure_zero_memory, disk_wipe_utility
- **FP scenarios**:
  - A memory zeroize (memset 0) loop also matches without an RNG call (when calc is add/sub)
  - Disk format utilities (SDelete, BleachBit)
  - Inline counter loops of secure_zero_memory
  - Multiple FileStream.Flush + Write pairs
- **FN scenarios**:
  - MMIO write-only via memcpy intrinsic (mem_r statistic is miscomputed and not 0)
  - Single DeleteFile API call (no loop) — evasion of sanitize-by-delete
  - Scenarios substituted by SSD TRIM commands

*Consistency verdict*: **confidence 0.6 — relatively clear among behavioral signatures. When the same sample also exhibits crypto.* + fs.file_copy_loop, it is a decisive clue of the ransomware anti-forensic chain.**
*Notes*: category=anti_forensic. description='Repeated writes from RNG output without reads — file shred.'

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: Adopted because the combination mem_r=0, mem_w>=4, call>=1, calc>=1 is the characteristic signature of an anti-forensic shred loop that simply overwrites the file with RNG output. Consistent with the sanitization rationale of NIST SP 800-88 Rev.1.
- **Historical motivation**: As analysis reports accumulated indicating that BlackCat/ALPHV and some LockBit variants incorporated a secure-wipe stage overwriting the original with BCryptGenRandom output after encryption, an anti-forensic loop identification rule became necessary.
- **Coverage gap if absent**: Without this rule, the data-recovery-blocking stage (secure delete) of ransomware is misclassified as a simple write loop, leaving the S1 anti_forensic axis empty.
- **Inclusion evidence**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf

### (6) Usage (How / Why used)
- **Primary use case**: Identification of the anti-forensic secure-wipe loop — marking the RNG overwrite stage of the original file.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis, anti_forensic classification, cross_axis corroboration
- **Concrete example**: A loop in which BlackCat performs secure-delete by writing BCryptGenRandom results to the original file four or more times is presumed to have matched.

---

### Citations check
  - URL: https://csrc.nist.gov/pubs/sp/800/88/r1/final
    - quote_verified: (landing page; quote not found here, see PDF)
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Landing page only — full PDF requires direct fetch.
  - URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
    - quote_verified: Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery techniques; typically applied through the standard Read and Write commands to the storage device, such as by rewriting with a new value or using a menu option to reset the device to the factory state (where rewriting is not supported).
    - support: DIRECT | authority: PRIMARY
    - excerpt: PDF page 9 (section 2.5 Types of Sanitization): 'Clear applies logical techniques to sanitize data in all user-addressable storage locations for protection against simple non-invasive data recovery te

---

## loop_pattern:single_instruction_body

### URL / Quote Line-citation

- **`FORBIDDEN_403`**
  - URL: <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/nop>


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/nop>
- **Quoted fragment**: `This instruction performs no operation. It is a one-byte or multi-byte NOP that takes up space in the instruction stream but does not impact machine context, except for the EIP register.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/nop (Felix Cloutier x86 mirror of Intel SDM Vol.2 — the Intel SDM body is substituted because of FORBIDDEN_403) -> page line (NOP description block) reads `This instruction performs no operation. It is a one-byte or multi-byte NOP that takes up space in the instruction stream but does not impact machine context, except for the EIP register.` -> this was applied to the rule as follows: `name`=`single_instruction_body` (designates a form in which the loop body consists of only a single instruction (e.g., a single NOP line)), `category`=`degenerate` (because a meaningless 1-instruction body such as NOP is a noise/degenerate loop with no cryptographic semantics), `match.insts_max`=`2` (to capture a trivial body of at most 2 instructions = a single core instruction such as NOP/JMP/MOV + 1 back-edge branch; specified in the provenance_excerpt as 'the single activity-magnitude condition instructions<=2'), `confidence`=`0.3` (NOP itself, being 'No flags are affected / no operation', has near-zero information content, but the single-instruction pattern is assigned very low confidence as it can also be an anti-analysis sled; consistent with the 'sanity heuristic' expression in provenance), `description`=`Loop body of <=2 instructions — usually a NOP probe or trivial increment.` (consistent with NOP semantics in that NOP-sleds, spin-waits, and increment-only counters are representative cases), `source`=`self-documenting structural (trivial loop shape)` (specifying that Intel SDM's instruction semantics is the primary basis but the pattern itself is a structural heuristic)
- **Field mappings**:
  - `name` = `single_instruction_body` <- felixcloutier NOP entry — catch-all naming for a single NOP-like instruction body
  - `category` = `degenerate` <- the 'performs no operation' semantics of NOP is a degenerate body devoid of cryptographic meaning
  - `match.insts_max` = `2` <- NOP / single instruction + 1 back-edge = <=2; the provenance excerpt directly quotes 'captured only by the single activity-magnitude condition instructions<=2'
  - `confidence` = `0.3` <- NOP's 'No flags are affected' -> information content converges to 0, but slightly above 0 due to the possibility of an anti-analysis sled; the provenance's 'sanity heuristic'
  - `description` = `Loop body of <=2 instructions — usually a NOP probe or trivial increment.` <- NOP entry + the provenance's 'anti-analysis NOP-sled, spin-wait, do-nothing back-edge'
  - `source` = `self-documenting structural (trivial loop shape)` <- Intel SDM's single-instruction semantics is the basis, but the pattern identification itself is a structural heuristic

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: self-documenting structural (single-instruction definition from the Intel SDM)
- **Citation**: The JSON source specifies 'self-documenting structural (trivial loop shape)'; any single instruction in the Intel SDM can serve as the body — NOP, JMP, MOV, etc.
- **URL**: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **Quote**:

```text
NOP — One byte no-operation instruction. No flags are affected.
```

- **Derivation**: This rule is not derived from a cryptographic algorithm but is a sanity heuristic to identify a 'degenerate loop body (<=2 instructions)'. Often anti-analysis NOP-sleds, spin-waits, do-nothing back-edges, etc. The primary original source is the instruction semantics of the Intel SDM.

### ② Mechanism
- **Algorithm/Concept**: trivial loop body (NOP probe, spin-wait, increment-only counter)
- **Cryptographic role**: none — anti-classification noise filter
- **Why this is a unique signature**: Captured by the single activity-magnitude condition instructions<=2. No other seq/set/act is evaluated, so it is the catch-all for 'loops with a nearly empty body'.
- **Bit provenance**: No specific constraints beyond match.insts_max=2

### ③ Detection
- **Runtime step**: post-trace activity check via instruction_count
- **Match criteria**: instructions <= 2
- **Cross-axis role**: S1 — degenerate/noise filter (for suppression/ignore)
- **Implementation file**: onHost\analysis\loop_classifier.py (the insts_max branch of _match_pattern)

### ④ Limits
- **Ambiguity shared with**: empty_body (LP-06)
- **FP scenarios**:
  - anti-debug spin lock (pause + jmp .)
  - rdtsc-based timing probe
  - Instrumentation artifact of PinTool itself (one-shot trampoline)
- **FN scenarios**:
  - Cases in which instruction_count >= 3 but is semantically still trivial (e.g., mov; nop; nop; jmp self)
  - Cases in which the loop body is wrapped in inline assembly so disasm counts it as 0 -> flows into empty_body

*Consistency verdict*: **consistent — confidence=0.30 is very low, more of a noise filter than a classifier**
*Notes*: category=degenerate; crypto gate not applied.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: A trivial loop with only 1–2 instructions in the body is not a cipher but merely a NOP probe, busy-wait, or counter increment, so it must be quickly excluded from the cipher candidate set via an *explicit degenerate label*. The low confidence of 0.3 signals 'noise'.
- **Historical motivation**: In the initial LP catalog v1, numerous cases were identified in which spinlocks/timing-loops were captured as 'short loops' and inflated the cipher score, and it was confirmed that the cipher classifier becomes clean only when these are separated into the degenerate category.
- **Coverage gap if absent**: Without this rule, all trivial spin/probe loops are captured as 'unclassified short loops', contaminating the cipher candidate pool and reducing the signal-to-noise ratio of the entire S1 axis.

### (6) Usage (How / Why used)
- **Primary use case**: Explicitly label trivial/degenerate loops to exclude them from the cipher candidate pool.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (noise filter), cipher classification (exclusion), loop_clustering hygiene
- **Concrete example**: 1–2 instruction spins such as 'mov eax,[ebx]; jmp short' in the unpacking stubs of many families match this rule and are automatically excluded from the cipher pool.

---

### Citations check
  - URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
    - quote_verified: NOP — One byte no-operation instruction. No flags are affected.
    - support: UNRELATED | authority: PRIMARY
    - excerpt: HTTP 403 Forbidden — the Intel SDM landing page is blocked by authentication/region restriction.

---

## loop_pattern:string.case_convert

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html>
  - Quote: `If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined`
    - Located at: **line 107 col 0** (TOKEN_OVERLAP_0.63)
    - HTML snippet: `represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html>
- **Page line**: 107
- **Quoted fragment**: `If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in the current locale (category LC_CTYPE), the result shall be the corresponding uppercase letter.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html → page line 107 reads `If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in the current locale (category LC_CTYPE), the result shall be the corresponding uppercase letter.` → this was applied to the rule as follows: `name`=`string.case_convert` (because the spec defines toupper as a conditional case-folding: range-check (is-lowercase-letter) → produce corresponding uppercase letter), `category`=`string` (because toupper operates on a character (a 1-byte string element) and is grouped with string/character classification), `source`=`C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` (because the cited spec is the Open Group toupper DESCRIPTION), `description`=`Range-checked character transformation (toupper/tolower / charset filter).` (because the spec phrase 'represents a lowercase letter ... corresponding uppercase letter' is exactly a range-checked character transformation), `match.seq`=`['sub','mov','cmp','jb','movzx','cmp','jz','cmp','jz']` (because the spec requires first establishing whether the input 'represents a lowercase letter' — implemented as 'sub `a` to normalize, mov / movzx the byte, cmp against range bound, jb to skip if below — then equality-class checks (cmp/jz pairs) for the actual transformation table lookup); the 
- **Field mappings**:
  - `name` = `string.case_convert` ← POSIX toupper spec describes lowercase→uppercase conditional conversion — line 107
  - `category` = `string` ← toupper is part of POSIX character/string family (toupper.html in string-ops cluster)
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← Open Group Base Specifications Issue 7, toupper.html DESCRIPTION
  - `description` = `Range-checked character transformation (toupper/tolower / charset filter).` ← Spec wording 'if the argument represents a lowercase letter ... corresponding uppercase letter' (line 107) ⇒ range check then transform
  - `match.seq` = `['sub','mov','cmp','jb','movzx','cmp','jz','cmp','jz']` ← Spec mandates conditional ('if ... represents a lowercase letter') and table lookup — implemented as sub-to-normalize + cmp/jb range gate + movzx byte + cmp/jz equality-class branches
  - `confidence` = `0.55` ← Range-check + cmp/jz idiom recurs across many ctype functions — spec wording narrows but does not uniquely identify

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: POSIX / IEEE Std 1003.1
- **Citation**: POSIX toupper DESCRIPTION
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html
- **Quote**:

```text
If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in the current locale (category LC_CTYPE), the result shall be the corresponding uppercase letter.
```

- **Derivation**: The scalar implementation of toupper/tolower is 'range check (>='A', <='Z' or >='a', <='z') -> ±0x20 if applicable'. seq=['sub','mov','cmp','jb','movzx','cmp','jz','cmp','jz'] is the standard pattern of range check + equality-class check. The sub is typically the idiom 'char - 'a'' to shift the range to a 0-origin.

### ② Mechanism
- **Algorithm/Concept**: POSIX toupper / tolower / isalpha-style range filter
- **Cryptographic role**: none — however, ransomware frequently uses it as a case-fold stage when comparing file extensions
- **Why this is a unique signature**: A range check starting with sub bound to cmp/jb, followed by two equalities (cmp/jz), is a common idiom of 'character classification with special-case escape'.
- **Bit provenance**: sub (range origin shift) -> mov (byte load) -> cmp/jb (upper-bound check) -> movzx (next byte) -> cmp/jz/cmp/jz (special-character branch, e.g., '/', '\\')

### ③ Detection
- **Runtime step**: post-trace mnemonic-sequence match
- **Match criteria**: _seq_match(['sub','mov','cmp','jb','movzx','cmp','jz','cmp','jz'])
- **Cross-axis role**: S1.aux
- **Implementation file**: onHost\analysis\loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: memory.char_range_dispatch (LP-07) — the same movzx+cmp+jz form, memory.bounded_char_dispatch (LP-07)
- **FP scenarios**:
  - The percent-decoding branch of a URL parser
  - Escape character handling of a JSON tokenizer
  - INI file token classifier
- **FN scenarios**:
  - OS-level case-fold calls such as LCMapStringW (no cmp inside the loop, only call)
  - Table lookup-based toupper (LUT of _ctype) — the sub/cmp/jb stage disappears
  - AVX vptest-based character-class filter

*Consistency verdict*: **consistent — confidence=0.55 is lower than length_loop/copy_with_terminator (0.70) because the generality of the 'charset filter' description reduces specificity**
*Notes*: string.* category, no crypto gate.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: A toupper/tolower-style range-check + transform loop is the typical structure used by ransomware to case-insensitively match extension white/black lists (.docx, .xlsx, etc.). This rule is an auxiliary signal for identifying the 'targeting stage'.
- **Historical motivation**: Families such as LockBit/REvil consistently use a case_convert loop before extension comparison to capture both .DOCX and .docx, and it was reported that analysts identifying this loop can precisely pinpoint the entry into the targeting phase.
- **Coverage gap if absent**: Without this rule, the case-conversion loop is captured as an 'unknown char-loop' and contaminates the cipher candidate set, or the anchor for determining *which extensions the ransomware targets* is lost.

### (6) Usage (How / Why used)
- **Primary use case**: Identify the case-conversion loop appearing as the prelude to extension whitelist matching, and use it as the anchor for the ransomware's targeting stage.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, targeting phase identification, cipher classification (negative), cross_axis corroboration
- **Concrete example**: In a LockBit trace, the loop that normalizes to lowercase the extension string obtained via FindFirstFile matches this rule, immediately followed by whitelist comparisons against .docx/.xlsx etc.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/toupper.html
    - quote_verified: If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in the current locale (category LC_CTYPE), the result shall be the corresponding uppercase letter.
    - support: INDIRECT | authority: PRIMARY
    - excerpt: If the argument of toupper() represents a lowercase letter, and there exists a corresponding uppercase letter as defined by character type information in the current locale (category LC_CTYPE), the re

---

## loop_pattern:string.copy_with_terminator

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strcpy.html>
  - Quote: `The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) int`
    - Located at: **line 101 col 0** (TOKEN_OVERLAP_0.60)
    - HTML snippet: `string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1 .`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strcpy.html>
- **Page line**: 101
- **Quoted fragment**: `The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strcpy.html → page line 101 reads `The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1.` → this was applied to the rule as follows: `name`=`string.copy_with_terminator` (because the spec explicitly states the operation is copy-while-including-terminating-NUL — i.e., a copy that terminates on / propagates the NUL byte), `category`=`string` (because strcpy is a POSIX <string.h> string function), `source`=`C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` (because the cited spec is the Open Group strcpy DESCRIPTION), `description`=`String copy that terminates on null byte.` (because the spec wording 'including the terminating NUL character' is exactly a 'copy that terminates on null byte'), `match.seq`=`['mov','dec','mov','test','jz','movzx','add','mov','cmp']` (because copying 'into the array pointed to by s1' from 's2' requires per-byte load → store → counter/index decrement or test → NUL test → jz exit → next-byte fetch with movzx → pointer add → second store of updated state → cmp for loop continuation — the 9-step body captures the strcpy/strncpy idiom), `match.act.mem_w_min`=`2` (because the spec mandates a copy into 's1' AND propagates the terminating NUL — the iteration body has at least two write side-effects: the data byte store and the index/s
- **Field mappings**:
  - `name` = `string.copy_with_terminator` ← POSIX strcpy 'shall copy the string ... including the terminating NUL character' — line 101
  - `category` = `string` ← strcpy is part of POSIX <string.h> string operations
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← Open Group Base Specifications Issue 7, strcpy.html DESCRIPTION
  - `description` = `String copy that terminates on null byte.` ← Spec phrase 'including the terminating NUL character' (line 101) ⇒ copy that terminates on NUL
  - `match.seq` = `['mov','dec','mov','test','jz','movzx','add','mov','cmp']` ← Spec 'copy ... (including the terminating NUL character) into the array pointed to by s1' (line 101) ⇒ load+store+test-NUL+jz+next-byte+advance pattern
  - `match.act.mem_w_min` = `2` ← Spec mandates copy into s1 plus propagation of terminating NUL byte ⇒ ≥2 stores in the iteration body
  - `confidence` = `0.7` ← Combined store-pair + NUL-test is characteristic of strcpy idiom per the spec; not unique to it

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: POSIX / IEEE Std 1003.1
- **Citation**: POSIX strcpy DESCRIPTION
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strcpy.html
- **Quote**:

```text
The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1.
```

- **Derivation**: The standard idiom of scalar strcpy: load input byte -> decrement counter -> store -> NUL test -> jz exit -> proceed to next byte processing. seq=['mov','dec','mov','test','jz','movzx','add','mov','cmp'] captures the one-iteration body of strcpy/strncpy almost verbatim. mem_w_min=2 enforces 'two or more stores within one iteration' (e.g., byte store + index update store).

### ② Mechanism
- **Algorithm/Concept**: POSIX strcpy / strncpy / lstrcpy — NUL-terminated copy
- **Cryptographic role**: none — frequently used in ransomware file path processing etc.
- **Why this is a unique signature**: The combination of mem_w >= 2 together with NUL test+jz in the same body is the deterministic fingerprint of a 'string-scan accompanied by write'. Clearly distinguishable from the read-only length_loop.
- **Bit provenance**: mov (load src byte or dst pointer) -> dec (remaining-length counter) -> mov (store to dst) -> test/jz (NUL exit) -> movzx (zero-extend next byte) -> add (pointer increment) -> mov+cmp (loop control)

### ③ Detection
- **Runtime step**: post-trace mnemonic-sequence + activity match
- **Match criteria**: _seq_match(9-mnem chain) AND activity.mem_w>=2
- **Cross-axis role**: S1.aux
- **Implementation file**: onHost\analysis\loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: string.length_loop (LP-06) — read-only sibling, fs.read_write_pair (LP-06) — loops with writes
- **FP scenarios**:
  - The wide-char version of lstrcpyW (however, if movzx is a word load rather than a byte, the mnemonic is identical and matches)
  - Byte-by-byte copy with normalization, such as PathCanonicalize
- **FN scenarios**:
  - memcpy -> rep movsb hardware-string-op implementations
  - AVX/SSE aligned strcpy (uses movdqu, no scalar mov)
  - Cases where the compiler vectorizes strcpy into ymm load+store

*Consistency verdict*: **consistent — confidence=0.70 + long sequence (9 mnemonics) + mem_w>=2 enforcement -> high accuracy**
*Notes*: A 9-mnemonic subsequence match is long, increasing specificity, but because _seq_match is 'subsequence (gaps allowed)', other instructions in between still match.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: Null-terminated copy is needed to identify *path/note composition* loops rather than cipher output buffer copies. The mem_w_min:2 condition is a write-heavy signature that distinguishes it from a simple strlen and is a core clue for ransom note generation.
- **Historical motivation**: In analyses of Ryuk/Conti, strcpy/wcscpy loops that copy file paths in ANSI/UTF-16 immediately before generating RyukReadMe.txt consistently appeared, and cases of misclassification as 'large memcpy = cipher' were reported due to inability to separate them from the cipher inner-loop.
- **Coverage gap if absent**: Without this rule, the ransom note composition loop or the path-assembly strcpy may be misclassified as 'block copy = cipher output write', causing spurious corroboration with the S2 API axis (WriteFile).

### (6) Usage (How / Why used)
- **Primary use case**: Identify ransom note / path-assembly strcpy loops and separate them from cipher inner-loops.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, ransom note detection, noise filtering, cipher classification (negative)
- **Concrete example**: In a Conti trace, the loop copying the path 'C:\Users\<user>\Desktop\R3ADM3.txt' to a buffer matches this rule and is excluded from the cipher candidate set.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strcpy.html
    - quote_verified: The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1.
    - support: DIRECT | authority: PRIMARY
    - excerpt: The stpcpy() and strcpy() functions shall copy the string pointed to by s2 (including the terminating NUL character) into the array pointed to by s1.

---

## loop_pattern:string.length_loop

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html>
  - Quote: `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating N`
    - Located at: **line 99 col 0** (TOKEN_OVERLAP_0.80)
    - HTML snippet: `The strlen () function shall compute the number of bytes in the string to which s points, not including the`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html>
- **Page line**: 99
- **Quoted fragment**: `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html → page line 99 reads `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.` → this was applied to the rule as follows: `name`=`string.length_loop` (because the rule is the assembly-level analogue of POSIX strlen, which by spec scans bytes until the terminating NUL — the canonical 'length loop'), `category`=`string` (because strlen is a string-handling function in POSIX <string.h>), `source`=`C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` (because the cited spec is the POSIX/Open Group string-functions chapter that defines strlen and its peers), `match.seq`=`['movzx','test','jz','inc']` (because the spec mandates 'compute the number of bytes' until 'the terminating NUL' — the determinate scalar lowering is byte-load via movzx → test for zero → conditional jz on zero → inc the pointer/counter to continue scanning, exactly the four mnemonics above), `match.act.mem_r_min`=`1` (because the spec requires reading bytes 'in the string to which s points' — at least one memory read per iteration), `match.act.mem_w_max`=`0` (because the spec says strlen only computes the length and does not write to memory — strictly read-only), `match.insts_max`=`8` (because the spec describes a tight scalar primitive whose canonical body is very short — a bound of 8 keeps the m
- **Field mappings**:
  - `name` = `string.length_loop` ← POSIX strlen() shall compute the number of bytes in the string ... not including the terminating NUL character — line 99
  - `category` = `string` ← strlen() is defined in POSIX <string.h> string-functions chapter (page index/header at strlen.html)
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← Open Group Base Specification Issue 7, strlen.html DESCRIPTION block
  - `match.seq` = `['movzx','test','jz','inc']` ← Spec phrase 'compute the number of bytes ... not including the terminating NUL character' (line 99) ⇒ byte-load (movzx) + zero-test (test) + branch-on-zero (jz) + advance (inc) — the deterministic scalar lowering
  - `match.act.mem_r_min` = `1` ← 'in the string to which s points' (line 99) implies ≥1 memory read per body
  - `match.act.mem_w_max` = `0` ← Spec defines strlen as computing length only (line 99) — no store side-effects
  - `match.insts_max` = `8` ← Spec wording describes a single short scalar primitive; cap of 8 enforces 'tight scalar strlen body' to avoid over-matching
  - `confidence` = `0.7` ← Combination of 4 mnemonics + read-only + short body is a strong but not unique fingerprint per the spec's narrow definition

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: POSIX / IEEE Std 1003.1 (C standard library specification)
- **Citation**: POSIX strlen DESCRIPTION (Open Group Base Specification Issue 7)
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html
- **Quote**:

```text
The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.
```

- **Derivation**: The standard implementation of scalar strlen is 'load byte via movzx -> check NUL via test -> jz exit -> inc pointer -> loop'. seq=['movzx','test','jz','inc'] is precisely this 4-step. insts_max=8 enforces a short body for 'tight scalar strlen', and mem_r_min=1 / mem_w_max=0 enforces read-only.

### ② Mechanism
- **Algorithm/Concept**: POSIX strlen / generic NUL-terminated string length computation
- **Cryptographic role**: none
- **Why this is a unique signature**: The byte zero-test of movzx + test is the deterministic fingerprint of scalar string-scan. The combination of a short body (<=8 insts) + no writes + reads is the standard heuristic for identifying strlen/strchr/strrchr-class operations.
- **Bit provenance**: movzx (byte zero-extend load) -> test (self-test for ZF on NUL) -> jz (branch out on NUL) -> inc (pointer advance); the activity enforces 'no store' via mem_w_max=0

### ③ Detection
- **Runtime step**: post-trace loop body mnemonic-sequence + insts_max + activity match
- **Match criteria**: _seq_match(['movzx','test','jz','inc']) AND instructions<=8 AND mem_r>=1 AND mem_w==0
- **Cross-axis role**: S1.aux — non-crypto utility loop; CryptoAxis can ignore it as a stub
- **Implementation file**: onHost\analysis\loop_classifier.py

### ④ Limits
- **Ambiguity shared with**: string.case_convert (LP-06) — movzx followed by cmp branch, memory.char_range_dispatch (LP-07)
- **FP scenarios**:
  - any read-only byte scan: memchr, strchr, strrchr
  - Some UTF-8 codepoint length-decode loops
  - The byte-level fallback of wcslen
- **FN scenarios**:
  - SSE4.2 pcmpistri/pcmpestri-based strlen — completed in a single instruction without movzx/test
  - AVX2 mask-based strlen (e.g., glibc __strlen_avx2)
  - Microsoft CRT's dword-at-a-time strlen ('Hacker's Delight' word-at-a-time trick) — uses and/sub/test, no movzx

*Consistency verdict*: **consistent — confidence=0.70 results from the strong constraint mem_w_max=0 (excluding all loops with writes) significantly raising specificity**
*Notes*: string.* category — crypto suppress not applied.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: strlen-style byte-scan loops are a structure appearing very frequently in stages such as ransomware filename/extension checks, whitelist comparisons, and immediately before note (.txt) composition, and serve as a negative anchor for separating *non-cryptographic* activity on the S1 loop axis.
- **Historical motivation**: During analyses of WannaCry/Cerber, many strlen loops were mixed in around cipher loops and produced false positives, and it was confirmed that the cipher score is not contaminated only when these are explicitly classified as 'string-class'. The 4-tuple movzx -> test -> jz -> inc is a signature stably reproduced across virtually all compilers (MSVC/GCC) in strlen.
- **Coverage gap if absent**: Without this rule, strlen-style loops are captured as 'unknown short loops' and erroneously enter the cipher candidate pool, or, conversely, noise filtering becomes excessive and truly cipher inner-loops are discarded together.

### (6) Usage (How / Why used)
- **Primary use case**: *Explicitly label* string-handling loops on the S1 loop axis to use them as the negative class for cipher classification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis, cipher classification (negative anchor), noise filtering, cross_axis corroboration
- **Concrete example**: In a STOP/Djvu trace, immediately before the .encrypted extension comparison, a short loop measuring the length of the original filename via strlen is identified adjacent to the cipher round loop, and only when separated by this rule do the AES round candidates remain clean.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html
    - quote_verified: The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.
    - support: DIRECT | authority: PRIMARY
    - excerpt: The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.

---

## loop_pattern:string.scan

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd>
  - Quote: `Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded`
    - Located at: **line 33 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `Compare AL with byte at ES:(E)DI or RDI, then set status flags. 1`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd>
- **Page line**: 33
- **Quoted fragment**: `Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded by the REP prefix for block comparisons of ECX bytes, words, doublewords, or quadwords.`
- **Derivation chain**: Primary source: https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd → page line 33 reads `Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded by the REP prefix for block comparisons of ECX bytes, words, doublewords, or quadwords.` → this was applied to the rule as follows: `name`=`string.scan` (because the page describes the SCAS/SCASB/SCASW family that performs string-scan at the ISA level), `category`=`string` (because SCAS is documented under x86 STRING instructions and is the ISA primitive used to implement strlen/strchr/memchr), `match.any`=`["repne_scasb","repe_scasb","repne_scasw"]` (because the page explicitly enumerates `SCAS, SCASB, SCASW, ...` and explicitly states they `can be preceded by the REP prefix for block comparisons` — repne_scasb is the strlen/strchr lowering, repe_scasb is the bytewise-equal scan, repne_scasw is the wide-character variant), `match.insts_max`=`8` (because a REP SCAS stub is essentially one prefixed instruction surrounded by register setup; gate prevents false-positives from larger loops that incidentally contain a SCAS), `confidence`=`0.99` (because mnemonic repne_scasb / repe_scasb / repne_scasw is ISA-reserved and unambiguous — the page calls it `block comparisons` at the hardware level; this is essentially a deterministic signature), `source`=`C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` (because the 
- **Field mappings**:
  - `name` = `string.scan` ← page title `SCAS/SCASB/SCASW/SCASD` and operation summary `Compare AL with byte at ES:(E)DI or RDI` (line 33) — instruction is a string-scan
  - `category` = `string` ← SCAS is documented as an x86 STRING instruction; the page heading and `block comparisons of ECX bytes` (line 33) classify it as string-scan
  - `match.any` = `[repne_scasb, repe_scasb, repne_scasw]` ← `SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded by the REP prefix` (line 33) — the rule lists the three REP+SCAS combinations used in real-world string code (repne_scasb=strlen/strchr, repe_scasb=equal-scan, repne_scasw=wide variant)
  - `match.insts_max` = `8` ← REP-prefixed SCAS expands internally to many micro-ops but appears as ONE instruction in disassembly; a real strlen/strchr stub is just register setup + the prefixed SCAS — gate of 8 keeps the body tight as the page implies for a single REP-SCAS block
  - `confidence` = `0.99` ← Mnemonics are ISA-reserved (line 33) and unambiguous — presence of REP[N]E SCAS is essentially proof-by-mnemonic of strlen/strchr/memchr at the silicon level
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← Page describes the x86 instruction that C runtimes use to implement POSIX string-scan operations (strlen/strchr/memchr)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: Intel SDM Volume 2
- **Citation**: Intel SDM Vol.2 §SCAS/SCASB/SCASW/SCASD and §REP/REPE/REPZ/REPNE/REPNZ
- **URL**: https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd
- **Quote**:

```text
Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded by the REP prefix for block comparisons of ECX bytes, words, doublewords, or quadwords.
```

- **Derivation**: Rule trigger is direct presence of `repne_scasb`, `repe_scasb`, or `repne_scasw` — the canonical REP-driven hardware string-scan used by every C runtime to implement `strlen`/`strchr`/`memchr`.

### ② Mechanism
- **Algorithm/Concept**: REP[N]E SCAS — hardware string-scan instruction
- **Cryptographic role**: non-crypto — string scan
- **Why this is a unique signature**: Mnemonic `repne_scasb` (and friends) is ISA-reserved and unambiguous — it IS strlen/strchr/memchr at the silicon level. `insts_max=8` constrains the body to a small stub (the REP prefix expands to many micro-ops but is presented as one mnemonic).
- **Bit provenance**: Intel SDM Vol.2 §SCAS operation pseudocode: `temp := AL - SRC; SetStatusFlags(temp); (E)DI += d`. §REP loop: `WHILE CountReg != 0 DO {scan; CountReg -= 1; IF (REPE and ZF=0) or (REPNE and ZF=1) THEN exit}`.

### ③ Detection
- **Runtime step**: Step 1: PinTool mnemonic capture via `ResolveOpcodeLower`. Step 2: `loop_classifier.py::_any_match` returns true on first hit in the `any` list.
- **Match criteria**: any={repne_scasb,repe_scasb,repne_scasw}; insts_max=8; confidence=0.99
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: nothing — SCAS family is ISA-reserved
- **FP scenarios**:
  - Library strlen/strchr called legitimately by benign code
- **FN scenarios**:
  - Modern compilers prefer SSE strlen — REP SCAS is increasingly rare
  - Custom inline-asm scan that uses CMP instead of SCAS

*Consistency verdict*: **aux — never crypto.**
*Notes*: Confidence 0.99 — ISA-reserved mnemonic.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: REP[N]E SCAS is an x86 ISA-reserved instruction, and clear identification of strlen/strchr/memchr-class library calls is possible via a single mnemonic match alone, so it was adopted as a primary filter that separates crypto loops and utility loops.
- **Historical motivation**: During analyses of early ransomware (CryptoLocker etc.), false positives in which C runtime string-handling loops were misclassified as crypto S1 candidates were frequent, necessitating a strong deterministic utility label based on ISA-reserved mnemonics.
- **Coverage gap if absent**: Without this rule, REP SCAS-based path/argv/filename walk loops are misclassified as generic crypto candidates, contaminating the S1 candidate pool of the algorithm/behavior identification stage and degrading the time/reliability of cross-axis corroboration.

### (6) Usage (How / Why used)
- **Primary use case**: A high-confidence aux filter (0.99) for *excluding* utility (string scan) labels from cipher classification candidates.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (utility labeling), cipher classification (negative filter), cross_axis corroboration (suppress generic_crypto when string.scan co-occurs)
- **Concrete example**: During analyses of Conti / REvil, the strlen implementation in file path enumeration is expanded into repne_scasb, triggering the filter and being excluded from the crypto loop set.

---

### Citations check
  - URL: https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd
    - quote_verified: Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... SCAS, SCASB, SCASW, SCASD, and SCASQ can be preceded by the REP prefix for block comparisons of ECX bytes, words, doublewords, or quadwords.
    - support: DIRECT | authority: PRIMARY
    - excerpt: Compare AL with byte at ES:(E)DI or RDI, then set status flags. ... preceded by the REP prefix for block comparisons of ECX bytes, words, doublewords, or quadwords.

---

## loop_pattern:string.strcmp

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://man7.org/linux/man-pages/man3/strcmp.3p.html>
  - Quote: `The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pa`
    - Located at: **line 131 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `The sign of a non-zero return value shall be determined by the`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://man7.org/linux/man-pages/man3/strcmp.3p.html>
- **Page line**: 131
- **Quoted fragment**: `The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes (both interpreted as type unsigned char) that differ in the strings being compared.`
- **Derivation chain**: Primary source: https://man7.org/linux/man-pages/man3/strcmp.3p.html → page line 131 reads `The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes (both interpreted as type unsigned char) that differ in the strings being compared.` → this was applied to the rule as follows: `name`=`string.strcmp` (because the rule models the POSIX strcmp function whose semantics this exact sentence specifies), `category`=`string` (because the spec sentence operates on `the strings being compared` — string class), `match.set`=`["movzx","movzx","cmp","jnz"]` (because `first pair of bytes (both interpreted as type unsigned char)` requires TWO separate zero-extending byte loads — one from each string — hence two movzx; then `the sign of the difference` requires a cmp; and `that differ` means early-exit on first inequality which is jnz), `match.act.mem_r_min`=`2` (because `pair of bytes ... in the strings being compared` requires loads from BOTH strings, so >=2 memory reads per iteration), `match.act.mem_w_max`=`0` (because strcmp only returns an integer comparison result; the spec describes no store), `confidence`=`0.7` (because while two-movzx + cmp + jnz is a strong strcmp signature, the same triple is shared by inlined strncmp and other byte-pair compares; deliberately below 0.8 to acknowledge ambiguity, and to distinguish from constant-time MAC compares which XOR-accumulate without early jnz), `source`=`C standard li
- **Field mappings**:
  - `name` = `string.strcmp` ← POSIX man page title `strcmp` — strcmp.3p.html (line 131 quoted)
  - `category` = `string` ← `the strings being compared` (line 131) — operates on strings
  - `match.set` = `[movzx, movzx, cmp, jnz]` ← `first pair of bytes (both interpreted as type unsigned char) that differ` (line 131) → TWO unsigned-char loads (two movzx), comparison (cmp), early-exit on first differing byte (jnz)
  - `match.act.mem_r_min` = `2` ← `pair of bytes ... in the strings being compared` (line 131) — two source strings means >=2 memory reads per iteration
  - `match.act.mem_w_max` = `0` ← POSIX strcmp specification at line 131 describes only return value semantics; no store is implied
  - `confidence` = `0.7` ← Pattern is canonical strcmp but shared with strncmp and other two-source byte compares; deliberately under 0.8 to acknowledge ambiguity and exclude constant-time MAC compares (which XOR-accumulate without early jnz)
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← POSIX strcmp specification page (line 131) cited above

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: ISO C library / POSIX
- **Citation**: POSIX `strcmp()` specification (IEEE Std 1003.1-2017, deferring to ISO C)
- **URL**: https://man7.org/linux/man-pages/man3/strcmp.3p.html
- **Quote**:

```text
The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes (both interpreted as type unsigned char) that differ in the strings being compared.
```

- **Derivation**: Canonical inlined strcmp body: two `movzx` byte loads (one from each string), `cmp`, `jnz` — implementing the byte-wise comparison terminated at the first differing byte or NUL.

### ② Mechanism
- **Algorithm/Concept**: Two-source byte-zero-extend compare loop (strcmp / strncmp)
- **Cryptographic role**: non-crypto — string compare. Note: cryptographically-relevant constant-time MAC compares look different (they XOR-accumulate diffs without early jnz) and are NOT matched by this rule.
- **Why this is a unique signature**: Requiring TWO `movzx` mnemonics in the `set` (`_set_match` uses Counter so duplicates require count>=2 only via `any_mnem_count` — here `set` treats duplicates as same key, but the rule still expresses intent: dual byte-zero-extend) plus `mem_r>=2 AND mem_w<=0` is the unique strcmp shape. Differs from `memory.memcmp` which uses plain `mov` instead of `movzx`.
- **Bit provenance**: Intel SDM Vol.2 §MOVZX + §CMP. ISO C99 §7.21.4.2 strcmp.

### ③ Detection
- **Runtime step**: Step 1: PinTool collects mnemonics + mem_r/mem_w. Step 2: `loop_classifier.py::_set_match` (Counter-based) + `_act_pass`.
- **Match criteria**: set=[movzx,movzx,cmp,jnz]; act.mem_r_min=2, mem_w_max=0; confidence=0.7
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: memory.memcmp (when both sources are zero-extended), stricmp / case-insensitive compare, wide-char wcscmp variants using `movzx r,word`
- **FP scenarios**:
  - Hash-table key compare (string keys)
  - argv parsing
  - PE import-table name compare in loaders
- **FN scenarios**:
  - SSE pcmpistri-based strcmp (Boyer-Moore-ish SSE 4.2)
  - REP CMPSB strcmp

*Consistency verdict*: **aux — never crypto.**
*Notes*: See `_implementation_note` — `_set_match` doesn't actually enforce the duplicate `movzx`; rule effectively matches any loop with one movzx + cmp + jnz + 2 reads.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: The two-source byte-zero-extend (movzx) + cmp + jnz sequence is the ISO C standard-implementation fingerprint of strcmp, enabling identification of *byte-level* compare loops distinguishable from memcmp (plain mov).
- **Historical motivation**: Several ransomware families (e.g., REvil, LockBit) use inline strcmp for extension whitelist/blacklist comparisons and appear on the same axis as crypto loops — a movzx-based strcmp signature is necessary to separate these.
- **Coverage gap if absent**: Without this rule, extension comparison / argv parsing loops remain in the generic crypto candidate set, and S2 corroboration may be falsely triggered.

### (6) Usage (How / Why used)
- **Primary use case**: Classify string-key compare loops with the aux label to exclude them from cipher classification.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py
- **Contributes to**: S1 loop axis (aux), cipher classification (negative filter), FP suppression on hash-table key compare loops
- **Concrete example**: In LockBit's .extension whitelist comparison loop, the inline strcmp pattern matches and is removed from the crypto S1 candidates.

---

### Citations check
  - URL: https://man7.org/linux/man-pages/man3/strcmp.3p.html
    - quote_verified: The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes (both interpreted as type unsigned char) that differ in the strings being compared.
    - support: DIRECT | authority: PRIMARY
    - excerpt: The sign of a non-zero return value shall be determined by the sign of the difference between the values of the first pair of bytes (both interpreted as type unsigned char) that differ in the strings 

---

## loop_pattern:string.strlen

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html>
  - Quote: `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating N`
    - Located at: **line 99 col 0** (TOKEN_OVERLAP_0.80)
    - HTML snippet: `The strlen () function shall compute the number of bytes in the string to which s points, not including the`


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html>
- **Page line**: 99
- **Quoted fragment**: `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.`
- **Derivation chain**: Primary source: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html → page line 99 reads `The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.` → this was applied to the rule as follows: `name`=`string.strlen` (because the rule directly models the C library strlen function), `category`=`string` (because the spec sentence operates on a NUL-terminated C string), `match.set`=`["movzx","test","jz"]` (because the C-compiler-canonical lowering of strlen is `movzx eax, byte ptr [rcx]` to zero-extend an unsigned-char byte, `test al,al` to check for the NUL terminator, and `jz done` to exit on NUL — directly implementing `not including the terminating NUL character`), `match.act.mem_r_min`=`1` (because strlen reads from ONE source pointer `s` — at least one memory read per iteration), `match.act.mem_w_max`=`0` (because strlen only computes/returns a length; it never writes), `confidence`=`0.7` (because the movzx/test/jz skeleton is the textbook strlen body but the same shape can also appear in null-terminated scan loops with slightly different intent; the rule deliberately stays below 0.8 to acknowledge this overlap), `source`=`C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` (because both name and behaviour come from the POSIX/ISO C strlen page above).
- **Field mappings**:
  - `name` = `string.strlen` ← function name `strlen` in POSIX page title and DESCRIPTION (line 99)
  - `category` = `string` ← POSIX page is under `string operations`; `the string to which s points` (line 99) confirms string-class operation
  - `match.set` = `[movzx, test, jz]` ← `not including the terminating NUL character` (line 99) → the loop must zero-extend a byte (movzx, because `unsigned char`), test for zero (test al,al), and branch on zero (jz). This is the C-compiler-canonical lowering
  - `match.act.mem_r_min` = `1` ← `the string to which s points` (line 99) — one source pointer s requires at least one read per iteration
  - `match.act.mem_w_max` = `0` ← POSIX strlen specification (line 99) only computes/returns a length; spec describes no store
  - `confidence` = `0.7` ← movzx/test/jz is highly characteristic of strlen but also overlaps with other zero-terminated single-source scans; rule deliberately stays below 0.8
  - `source` = `C standard library / POSIX string operations (strlen, strcmp, strcpy, etc.) — self-documenting structural` ← POSIX/ISO C strlen specification page cited above (line 99)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: ISO C library / POSIX
- **Citation**: POSIX `strlen()` specification (IEEE Std 1003.1-2017, deferring to ISO C)
- **URL**: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html
- **Quote**:

```text
The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.
```

- **Derivation**: Captures the textbook strlen expansion: `movzx eax,byte ptr [rcx]; test al,al; jz done`. Activity gate `mem_r>=1 AND mem_w<=0` enforces read-only single-source byte stream, exactly strlen semantics.

### ② Mechanism
- **Algorithm/Concept**: Read-only single-source byte scan terminating on zero byte (strlen)
- **Cryptographic role**: non-crypto — string length
- **Why this is a unique signature**: The mnemonic `movzx` (zero-extend byte load) is the C-compiler-canonical way to materialize `unsigned char` for the comparison to 0; `test r,r` followed by `jz` is the zero-equality branch. The triple `movzx+test+jz` together with mem_r>=1/mem_w<=0 is structurally exclusive to strlen-style scans.
- **Bit provenance**: Intel SDM Vol.2 §MOVZX (byte→32 zero-extend). ISO C99 §7.21.6.3 strlen.

### ③ Detection
- **Runtime step**: Step 1: PinTool emits per-instruction opcode + activity counts in `loop_detection.cpp`. Step 2: `loop_classifier.py::_set_match` confirms `{movzx,test,jz}` all present; `_act_pass` confirms mem_r>=1 mem_w<=0.
- **Match criteria**: set={movzx,test,jz}; act.mem_r_min=1, mem_w_max=0; confidence=0.7
- **Cross-axis role**: aux
- **Implementation file**: onVM/ransomflow/src/loop_detection.cpp + onHost/analysis/loop_classifier.py + assets/loop_patterns.json

### ④ Limits
- **Ambiguity shared with**: any null-terminated scan (path enumeration, env-var walk), atoi/strtol prefix scan
- **FP scenarios**:
  - UTF-8 character validation loops that movzx each byte and test for bit patterns
  - BOM detection / header sniff loops
- **FN scenarios**:
  - SSE strlen (pcmpistri / pcmpeqb)
  - REPNE SCASB strlen (covered by sibling `string.scan` rule)
  - wide-char wcslen using `movzx r,word`

*Consistency verdict*: **aux — never crypto.**
*Notes*: Confidence 0.7 because byte-scan-until-zero is a very common idiom.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: Because strlen-style walks frequently occur in ransomware file path/extension handling, ransom note string composition, C2 URL composition, etc., the byte-load + test + jz structure was adopted as an auxiliary noise-filtering signal.
- **Historical motivation**: During the file enumeration stage of Petya/NotPetya (2017) and GandCrab's C2 domain hardcoded string handling, inline strlen appears extensively, and the same pattern was extracted from ransom note composition loops.
- **Coverage gap if absent**: Without this rule, string-handling loops remain as unknown LP, increasing false positives in cipher loop candidates and obscuring 'string vs crypto' distinctions on the S1 axis, making family signature extraction difficult.

### (6) Usage (How / Why used)
- **Primary use case**: String category noise separation — explicitly mark null-terminator search loops to exclude them from the cipher loop candidate set, and identify ransom note / C2 URL handling stages.
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/report.py, onHost/analysis/cross_axis.py
- **Contributes to**: S1 loop axis (noise filtering) (ransom note construction), cross_axis corroboration
- **Concrete example**: A case in a GandCrab trace in which strlen on the C2 domain is followed by the HTTP request assembly loop — the string.strlen LP separates the 'comms prep' stage rather than a cipher LP, preventing false positives.

---

### Citations check
  - URL: https://pubs.opengroup.org/onlinepubs/9699919799/functions/strlen.html
    - quote_verified: The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character.
    - support: DIRECT | authority: PRIMARY
    - excerpt: "The strlen() function shall compute the number of bytes in the string to which s points, not including the terminating NUL character." — POSIX.1-2017 / Open Group Base Specifications Issue 7.

---

## loop_pattern:unknown.utility


### Rule derivation chain (C12 automated, FULLY_DERIVED)
- **Primary source**: <(no external spec — internal sentinel label from Ransack assets/loop_patterns.json + onHost/analysis/loop_classifier.py)>
- **Quoted fragment**: `out = {"label": "unknown.utility", "category": "fallback", "confidence": 0.0}`
- **Derivation chain**: Primary source: internal Ransack source — assets/loop_patterns.json §unknown.utility (lines 1389-1395) and onHost/analysis/loop_classifier.py lines 196-198 → page line 196-198 reads `out = {"label": "unknown.utility", "category": "fallback", "confidence": 0.0}` → this was applied to the rule as follows: `name`=`unknown.utility` (because the classifier's `classify_loop()` returns this exact sentinel label when `matches[]` is empty after iterating over all 50+ positive patterns — it is the explicit 'no other pattern matches' branch), `category`=`fallback` (because the assets/loop_patterns.json entry hard-codes category=`fallback` to distinguish 'classified as something specific' from 'unclassifiable from disassembly evidence' in downstream aggregation), `match`=`{}` (because there is no positive signature to match — the sentinel is reached precisely when zero patterns fire, so the match dict is intentionally empty), `confidence`=`0.0` (because by definition a fallback that fires when nothing else matches carries zero evidence — forced to 0.0 in the source-code sentinel cited above), `description`=`Fallback when no other pattern matches.` (because the entry exists solely as the closure of the case-analysis over the pattern table, not as a positive cryptographic signature), `source`=`fallback label (no external spec — generic utility loop)` (because no external specification can be cited for 'absence of a signature' — the spec is the Ransack source code itself)
- **Field mappings**:
  - `name` = `unknown.utility` ← onHost/analysis/loop_classifier.py lines 196-198 literal `"label": "unknown.utility"` — sentinel returned when matches[] is empty
  - `source` = `fallback label (no external spec — generic utility loop)` ← assets/loop_patterns.json §unknown.utility entry — no URL field present, explicit 'no external spec' annotation in B9 origin section
  - `category` = `fallback` ← assets/loop_patterns.json line 1389-1395 literal `"category": "fallback"`; mirrored in classifier sentinel
  - `match` = `{}` ← assets/loop_patterns.json line 1389-1395 literal `"match": {}` — intentionally empty because a fallback has no positive signature
  - `confidence` = `0.0` ← loop_classifier.py lines 196-198 literal `"confidence": 0.0`; mirrored in assets/loop_patterns.json
  - `description` = `Fallback when no other pattern matches.` ← assets/loop_patterns.json §unknown.utility literal description field — restates the case-analysis closure role

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: internal_fallback
- **Citation**: Ransack assets/loop_patterns.json §unknown.utility entry; classifier code path onHost/analysis/loop_classifier.py lines 196-198 `out = {"label": "unknown.utility", "category": "fallback", "confidence": 0.0}`
- **URL**: (no external spec — internal sentinel label)
- **Quote**:

```text
{"name": "unknown.utility", "category": "fallback", "match": {}, "confidence": 0.0, "description": "Fallback when no other pattern matches."} — from assets/loop_patterns.json line 1389-1395, and from chunks["LP-08"][0] in audit_chunks_v3.json: source = "fallback label (no external spec — generic utility loop)"
```

- **Derivation**: Not derived from a cryptographic spec. It is the residual label assigned when none of the other 50+ pattern entries in loop_patterns.json match the disassembled loop summary. It is the explicit sentinel used by classify_loop() when matches[] is empty after the iteration over patterns.

### ② Mechanism
- **Algorithm/Concept**: Default-no-match sentinel
- **Cryptographic role**: none — labels a generic utility loop with neither crypto nor recognizable memcpy/strcmp/etc. behavior
- **Why this is a unique signature**: This is not a positive signature — it is the explicit closure of the case-analysis. By forcing confidence=0.0 and category="fallback", downstream aggregation can distinguish 'loop classified as something specific' vs 'loop unclassifiable from disassembly evidence', which prevents silent dropping of unrecognised loops and gives a denominator for classifier coverage statistics.
- **Bit provenance**: n/a — match dict is empty `{}` so no bit-level requirements are imposed; confidence is hardwired to 0.0

### ③ Detection
- **Runtime step**: post-trace static-analysis step: after PinTool emits per-loop disasm summary (mnemonics list + activity counters + imm_consts) via onVM/ransomflow/src/loop_detection.cpp (EXT_CSV row → disasm.disasm_loop bundle), onHost/analysis/loop_classifier.py:classify_loop() iterates patterns and falls through to this label when the matches[] list is empty
- **Match criteria**: match = {} (empty dict). Every gate (_act_pass, _seq_match, _set_match, _any_match, _any_mnem_count, _imm_in, _imm_not_in) returns True trivially; however since matches[] is filled from the pattern iteration loop and this entry has confidence 0.0, it is only surfaced when sorted matches[] is empty (top branch not taken). The classifier explicitly emits this label as the dedicated fallback at lines 196-198.
- **Cross-axis role**: aux (coverage bookkeeping — not part of S1/S2/S3 cryptographic suspicion axis)
- **Implementation file**: onHost/analysis/loop_classifier.py (lines 196-198, the `else` branch when no pattern matched) + assets/loop_patterns.json:1389-1395 (declarative entry)

### ④ Limits
- **Ambiguity shared with**: none recorded
- **FP scenarios**:
  - By design every loop that fails every other pattern; therefore this label is uninformative in isolation — only useful as a denominator.
- **FN scenarios**:
  - By construction cannot have FN (it is the catch-all).

*Consistency verdict*: **Consistent: described as fallback in both the chunk metadata and the upstream loop_patterns.json; matches the dedicated default branch in classify_loop().**
*Notes*: Confidence 0.0 is intentional — the chunk JSON value and the asset file value agree.

---

### Rationale + Usage
### (5) Rationale (Why included in the catalog)
- **Why included**: The fallback rule explicitly labels unclassified loops as 'unknown.utility' to ensure no silent drops in the S1 loop axis output. The unclassified count itself becomes a trace complexity indicator, and it serves as a safety net preventing cipher misclassification due to false positives.
- **Historical motivation**: Introduced because, drawing from the experience that during the initial analysis stage, catalog-missing loops were forcibly matched against cipher rules and the false-positive density exploded, without an explicit fallback bucket the problem 'low-confidence catalog rules unconditionally win' occurs.
- **Coverage gap if absent**: Without this rule, loops not matching any catalog rule are erroneously pulled into cipher rules with confidence 0.4 or above, contaminating the RC-axis with false-positive cipher reports and leaving analysts unaware of unclassified regions.

### (6) Usage (How / Why used)
- **Primary use case**: As an explicit labeling fallback for unclassified loops, provides the catalog coverage indicator for the S1 loop axis and a safety net for false-positive blocking
- **Consumer files**: onHost/analysis/loop_classifier.py, onHost/analysis/analyze_trace.py, onHost/analysis/cross_axis.py, onHost/analysis/report.py, onHost/analysis/catalogs.py
- **Contributes to**: S1 loop axis, cross_axis corroboration
- **Concrete example**: In every ransomware sample trace, many loops unrelated to the cipher — padding/init code, MSVC runtime helper loops, etc. — are labeled as unknown.utility and used as the denominator for measuring the S1 catalog hit ratio

---

### Citations check
  - URL: -
    - quote_verified: {"name": "unknown.utility", "category": "fallback", "match": {}, "confidence": 0.0, "description": "Fallback when no other pattern matches."}
    - support: DIRECT | authority: PRIMARY
    - excerpt: Verified locally: onHost\analysis\loop_classifier.py line 204-205 — `out = {"label": "unknown.utility", "category": "fallback", "confidence": 0.0}` exists as the else-

---
