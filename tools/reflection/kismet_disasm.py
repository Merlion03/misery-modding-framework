#!/usr/bin/env python3
"""STRICTLY READ-ONLY. A Kismet bytecode disassembler for UE 5.4.4, transcribed
from the engine's own walker.

WHY THIS EXISTS. A byte scan can tell you that a function's bytecode *contains*
an FProperty pointer, but not whether that property is read, written, compared
against null, or merely the l-value of an unrelated assignment. Answering "what
does the widget actually do with this field" needs the real expression tree.

WHY IT IS TRUSTWORTHY. The operand grammar is not guessed: every case below is a
transcription of `UStruct::SerializeExpr` as expanded from
Engine/Source/Runtime/CoreUObject/Public/UObject/ScriptSerialization.h:169-635,
with the operand widths taken from the macros in the same file:

  XFERPTR / XFER_PROP_POINTER / XFER_FUNC_POINTER / XFER_OBJECT_POINTER /
  XFERTOBJPTR                       -> ScriptPointerType, 8 bytes
  XFERNAME / XFER_FUNC_NAME         -> FScriptName, 12 bytes
                                       (NameTypes.h:440-470: two FNameEntryId +
                                        uint32 Number)
  CodeSkipSizeType                  -> uint32, because Script.h:61-67 defines it
                                       as uint16 only when
                                       SCRIPT_LIMIT_BYTECODE_TO_64KB is 1, and
                                       Script.h:60 sets it to 0.

Large-world-coordinates branches (EX_VectorConst / EX_RotationConst /
EX_TransformConst) take the >= LARGE_WORLD_COORDINATES arm, which is the only
one a UE5 package can be saved with.

FAIL LOUD. An opcode with no case raises. A silent skip would let the walker
resynchronise on operand bytes and emit a confident, wrong listing -- exactly
the failure mode this module exists to avoid.
"""
import struct

PTR = 8
SCRIPTNAME = 12
CODESKIP = 4

(EX_LocalVariable, EX_InstanceVariable, EX_DefaultVariable) = (0x00, 0x01, 0x02)
EX_Return, EX_Jump, EX_JumpIfNot = 0x04, 0x06, 0x07
EX_Assert, EX_Nothing, EX_NothingInt32 = 0x09, 0x0B, 0x0C
EX_Let, EX_BitFieldConst, EX_ClassContext = 0x0F, 0x11, 0x12
EX_MetaCast, EX_LetBool, EX_EndParmValue = 0x13, 0x14, 0x15
EX_EndFunctionParms, EX_Self, EX_Skip = 0x16, 0x17, 0x18
EX_Context, EX_Context_FailSilent = 0x19, 0x1A
EX_VirtualFunction, EX_FinalFunction = 0x1B, 0x1C
EX_IntConst, EX_FloatConst, EX_StringConst = 0x1D, 0x1E, 0x1F
EX_ObjectConst, EX_NameConst, EX_RotationConst = 0x20, 0x21, 0x22
EX_VectorConst, EX_ByteConst, EX_IntZero, EX_IntOne = 0x23, 0x24, 0x25, 0x26
EX_True, EX_False, EX_TextConst, EX_NoObject = 0x27, 0x28, 0x29, 0x2A
EX_TransformConst, EX_IntConstByte, EX_NoInterface = 0x2B, 0x2C, 0x2D
EX_DynamicCast, EX_StructConst, EX_EndStructConst = 0x2E, 0x2F, 0x30
EX_SetArray, EX_EndArray, EX_PropertyConst = 0x31, 0x32, 0x33
EX_UnicodeStringConst, EX_Int64Const, EX_UInt64Const = 0x34, 0x35, 0x36
EX_DoubleConst, EX_Cast, EX_SetSet, EX_EndSet = 0x37, 0x38, 0x39, 0x3A
EX_SetMap, EX_EndMap, EX_SetConst, EX_EndSetConst = 0x3B, 0x3C, 0x3D, 0x3E
EX_MapConst, EX_EndMapConst, EX_Vector3fConst = 0x3F, 0x40, 0x41
EX_StructMemberContext, EX_LetMulticastDelegate = 0x42, 0x43
EX_LetDelegate, EX_LocalVirtualFunction = 0x44, 0x45
EX_LocalFinalFunction, EX_LocalOutVariable = 0x46, 0x48
EX_DeprecatedOp4A, EX_InstanceDelegate = 0x4A, 0x4B
EX_PushExecutionFlow, EX_PopExecutionFlow = 0x4C, 0x4D
EX_ComputedJump, EX_PopExecutionFlowIfNot = 0x4E, 0x4F
EX_Breakpoint, EX_InterfaceContext, EX_ObjToInterfaceCast = 0x50, 0x51, 0x52
EX_EndOfScript, EX_CrossInterfaceCast, EX_InterfaceToObjCast = 0x53, 0x54, 0x55
EX_WireTracepoint, EX_SkipOffsetConst = 0x5A, 0x5B
EX_AddMulticastDelegate, EX_ClearMulticastDelegate = 0x5C, 0x5D
EX_Tracepoint, EX_LetObj, EX_LetWeakObjPtr = 0x5E, 0x5F, 0x60
EX_BindDelegate, EX_RemoveMulticastDelegate = 0x61, 0x62
EX_CallMulticastDelegate, EX_LetValueOnPersistentFrame = 0x63, 0x64
EX_ArrayConst, EX_EndArrayConst, EX_SoftObjectConst = 0x65, 0x66, 0x67
EX_CallMath, EX_SwitchValue, EX_InstrumentationEvent = 0x68, 0x69, 0x6A
EX_ArrayGetByRef, EX_ClassSparseDataVariable, EX_FieldPathConst = 0x6B, 0x6C, 0x6D
EX_AutoRtfmTransact, EX_AutoRtfmStopTransact, EX_AutoRtfmAbortIfNot = 0x70, 0x71, 0x72

NAMES = {v: k for k, v in list(globals().items()) if k.startswith("EX_")}

NO_OPERAND = {EX_Nothing, EX_EndOfScript, EX_EndFunctionParms, EX_EndStructConst,
              EX_EndArray, EX_EndArrayConst, EX_EndSet, EX_EndMap, EX_EndSetConst,
              EX_EndMapConst, EX_IntZero, EX_IntOne, EX_True, EX_False, EX_NoObject,
              EX_NoInterface, EX_Self, EX_EndParmValue, EX_PopExecutionFlow,
              EX_DeprecatedOp4A, EX_WireTracepoint, EX_Tracepoint, EX_Breakpoint}


class UnknownOpcode(Exception):
    pass


class NullResolver:
    def prop(self, p):
        return "FProperty(0x%x)" % p

    def obj(self, p):
        return "UObject(0x%x)" % p

    def func(self, p):
        return "UFunction(0x%x)" % p

    def name(self, entry_id, number):
        return "FName(%d:%d)" % (entry_id, number)


class Disassembler:
    def __init__(self, code, resolver=None):
        self.c = code
        self.n = len(code)
        self.r = resolver or NullResolver()
        self.out = []

    # -- primitive readers ------------------------------------------------
    def u8(self, i):
        return self.c[i], i + 1

    def u16(self, i):
        return struct.unpack_from("<H", self.c, i)[0], i + 2

    def i32(self, i):
        return struct.unpack_from("<i", self.c, i)[0], i + 4

    def u32(self, i):
        return struct.unpack_from("<I", self.c, i)[0], i + 4

    def i64(self, i):
        return struct.unpack_from("<q", self.c, i)[0], i + 8

    def u64(self, i):
        return struct.unpack_from("<Q", self.c, i)[0], i + 8

    def f32(self, i):
        return struct.unpack_from("<f", self.c, i)[0], i + 4

    def f64(self, i):
        return struct.unpack_from("<d", self.c, i)[0], i + 8

    def sname(self, i):
        eid, num = struct.unpack_from("<II", self.c, i)
        return (eid, num), i + SCRIPTNAME

    def astring(self, i):
        j = i
        while j < self.n and self.c[j]:
            j += 1
        return self.c[i:j].decode("latin-1"), j + 1

    def ustring(self, i):
        j = i
        while j + 1 < self.n and (self.c[j] or self.c[j + 1]):
            j += 2
        return self.c[i:j].decode("utf-16-le", "replace"), j + 2

    # -- emit -------------------------------------------------------------
    def emit(self, off, op, depth, text):
        self.out.append({"offset": off, "op": NAMES.get(op, "EX_?%02X" % op),
                         "opcode": op, "depth": depth, "text": text})

    # -- the walker -------------------------------------------------------
    def expr(self, i, depth=0):
        """Returns (next_index, opcode). Mirrors UStruct::SerializeExpr."""
        off = i
        op, i = self.u8(i)
        E = self.emit

        if op in NO_OPERAND:
            E(off, op, depth, "")
            return i, op

        if op == EX_Cast:
            kind, i = self.u8(i)
            E(off, op, depth, "kind=%d" % kind)
            i, _ = self.expr(i, depth + 1)
        elif op in (EX_ObjToInterfaceCast, EX_CrossInterfaceCast, EX_InterfaceToObjCast,
                    EX_MetaCast, EX_DynamicCast):
            cls, i = self.u64(i)
            E(off, op, depth, self.r.obj(cls))
            i, _ = self.expr(i, depth + 1)
        elif op == EX_Let:
            prop, i = self.u64(i)
            E(off, op, depth, self.r.prop(prop))
            i, _ = self.expr(i, depth + 1)
            i, _ = self.expr(i, depth + 1)
        elif op in (EX_LetObj, EX_LetWeakObjPtr, EX_LetBool, EX_LetDelegate,
                    EX_LetMulticastDelegate, EX_AddMulticastDelegate,
                    EX_RemoveMulticastDelegate, EX_ArrayGetByRef):
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
            i, _ = self.expr(i, depth + 1)
        elif op == EX_LetValueOnPersistentFrame:
            prop, i = self.u64(i)
            E(off, op, depth, self.r.prop(prop))
            i, _ = self.expr(i, depth + 1)
        elif op == EX_StructMemberContext:
            prop, i = self.u64(i)
            E(off, op, depth, self.r.prop(prop))
            i, _ = self.expr(i, depth + 1)
        elif op == EX_Jump:
            tgt, i = self.u32(i)
            E(off, op, depth, "-> 0x%x" % tgt)
        elif op == EX_PushExecutionFlow:
            tgt, i = self.u32(i)
            E(off, op, depth, "push 0x%x" % tgt)
        elif op == EX_SkipOffsetConst:
            tgt, i = self.u32(i)
            E(off, op, depth, "0x%x" % tgt)
        elif op == EX_ComputedJump:
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
        elif op in (EX_LocalVariable, EX_InstanceVariable, EX_DefaultVariable,
                    EX_LocalOutVariable, EX_ClassSparseDataVariable, EX_PropertyConst):
            prop, i = self.u64(i)
            E(off, op, depth, self.r.prop(prop))
        elif op in (EX_InterfaceContext, EX_ClearMulticastDelegate, EX_FieldPathConst,
                    EX_PopExecutionFlowIfNot, EX_Return, EX_AutoRtfmAbortIfNot):
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
        elif op == EX_NothingInt32:
            v, i = self.i32(i)
            E(off, op, depth, str(v))
        elif op == EX_InstrumentationEvent:
            if self.c[i] == 1:  # EScriptInstrumentation::InlineEvent
                i += SCRIPTNAME
            i += 1
            E(off, op, depth, "")
        elif op in (EX_CallMath, EX_LocalFinalFunction, EX_FinalFunction,
                    EX_CallMulticastDelegate):
            fn, i = self.u64(i)
            E(off, op, depth, self.r.func(fn))
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_EndFunctionParms:
                    break
        elif op in (EX_LocalVirtualFunction, EX_VirtualFunction):
            (eid, num), i = self.sname(i)
            E(off, op, depth, self.r.name(eid, num))
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_EndFunctionParms:
                    break
        elif op in (EX_ClassContext, EX_Context, EX_Context_FailSilent):
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)          # object expression
            skip, i = self.u32(i)                   # code offset for NULL
            rvalue, i = self.u64(i)                 # FField* r-value property
            self.out[-1]["text"] = "null_skip=0x%x rvalue=%s" % (
                skip, self.r.prop(rvalue) if rvalue else "None")
            i, _ = self.expr(i, depth + 1)          # context expression
        elif op == EX_IntConst:
            v, i = self.i32(i)
            E(off, op, depth, str(v))
        elif op == EX_Int64Const:
            v, i = self.i64(i)
            E(off, op, depth, str(v))
        elif op == EX_UInt64Const:
            v, i = self.u64(i)
            E(off, op, depth, str(v))
        elif op == EX_FloatConst:
            v, i = self.f32(i)
            E(off, op, depth, repr(v))
        elif op == EX_DoubleConst:
            v, i = self.f64(i)
            E(off, op, depth, repr(v))
        elif op == EX_StringConst:
            v, i = self.astring(i)
            E(off, op, depth, repr(v))
        elif op == EX_UnicodeStringConst:
            v, i = self.ustring(i)
            E(off, op, depth, repr(v))
        elif op == EX_TextConst:
            kind, i = self.u8(i)
            E(off, op, depth, "literal_type=%d" % kind)
            if kind == 0:        # Empty
                pass
            elif kind == 1:      # LocalizedText
                for _ in range(3):
                    i, _ = self.expr(i, depth + 1)
            elif kind in (2, 3):  # InvariantText, LiteralString
                i, _ = self.expr(i, depth + 1)
            elif kind == 4:      # StringTableEntry
                _, i = self.u64(i)
                for _ in range(2):
                    i, _ = self.expr(i, depth + 1)
            else:
                raise UnknownOpcode("EX_TextConst literal type %d at 0x%x" % (kind, off))
        elif op == EX_ObjectConst:
            p, i = self.u64(i)
            E(off, op, depth, self.r.obj(p))
        elif op == EX_SoftObjectConst:
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
        elif op == EX_NameConst:
            (eid, num), i = self.sname(i)
            E(off, op, depth, self.r.name(eid, num))
        elif op == EX_RotationConst:
            a, i = self.i64(i)
            b, i = self.i64(i)
            c, i = self.i64(i)
            E(off, op, depth, "%d,%d,%d" % (a, b, c))
        elif op == EX_VectorConst:
            a, i = self.f64(i)
            b, i = self.f64(i)
            c, i = self.f64(i)
            E(off, op, depth, "%r,%r,%r" % (a, b, c))
        elif op == EX_Vector3fConst:
            a, i = self.f32(i)
            b, i = self.f32(i)
            c, i = self.f32(i)
            E(off, op, depth, "%r,%r,%r" % (a, b, c))
        elif op == EX_TransformConst:
            vals = []
            for _ in range(10):
                v, i = self.f64(i)
                vals.append(v)
            E(off, op, depth, ",".join(repr(v) for v in vals))
        elif op == EX_StructConst:
            s, i = self.u64(i)
            sz, i = self.i32(i)
            E(off, op, depth, "%s size=%d" % (self.r.obj(s), sz))
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_EndStructConst:
                    break
        elif op == EX_SetArray:
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_EndArray:
                    break
        elif op in (EX_SetSet, EX_SetMap):
            E(off, op, depth, "")
            i, _ = self.expr(i, depth + 1)
            cnt, i = self.i32(i)
            end = EX_EndSet if op == EX_SetSet else EX_EndMap
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == end:
                    break
        elif op in (EX_ArrayConst, EX_SetConst):
            prop, i = self.u64(i)
            cnt, i = self.i32(i)
            E(off, op, depth, "%s n=%d" % (self.r.prop(prop), cnt))
            end = EX_EndArrayConst if op == EX_ArrayConst else EX_EndSetConst
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == end:
                    break
        elif op == EX_MapConst:
            kp, i = self.u64(i)
            vp, i = self.u64(i)
            cnt, i = self.i32(i)
            E(off, op, depth, "%s/%s n=%d" % (self.r.prop(kp), self.r.prop(vp), cnt))
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_EndMapConst:
                    break
        elif op == EX_BitFieldConst:
            prop, i = self.u64(i)
            v, i = self.u8(i)
            E(off, op, depth, "%s=%d" % (self.r.prop(prop), v))
        elif op in (EX_ByteConst, EX_IntConstByte):
            v, i = self.u8(i)
            E(off, op, depth, str(v))
        elif op == EX_JumpIfNot:
            tgt, i = self.u32(i)
            E(off, op, depth, "-> 0x%x if not" % tgt)
            i, _ = self.expr(i, depth + 1)
        elif op == EX_Assert:
            line, i = self.u16(i)
            dbg, i = self.u8(i)
            E(off, op, depth, "line=%d" % line)
            i, _ = self.expr(i, depth + 1)
        elif op == EX_Skip:
            sz, i = self.u32(i)
            E(off, op, depth, "skip=0x%x" % sz)
            i, _ = self.expr(i, depth + 1)
        elif op == EX_InstanceDelegate:
            (eid, num), i = self.sname(i)
            E(off, op, depth, self.r.name(eid, num))
        elif op == EX_BindDelegate:
            (eid, num), i = self.sname(i)
            E(off, op, depth, self.r.name(eid, num))
            i, _ = self.expr(i, depth + 1)
            i, _ = self.expr(i, depth + 1)
        elif op == EX_SwitchValue:
            ncases, i = self.u16(i)
            after, i = self.u32(i)
            E(off, op, depth, "cases=%d end=0x%x" % (ncases, after))
            i, _ = self.expr(i, depth + 1)          # index term
            for _ in range(ncases):
                i, _ = self.expr(i, depth + 1)      # case value
                _, i = self.u32(i)                  # offset to next case
                i, _ = self.expr(i, depth + 1)      # case term
            i, _ = self.expr(i, depth + 1)          # default term
        elif op == EX_AutoRtfmTransact:
            tid, i = self.i32(i)
            tgt, i = self.u32(i)
            E(off, op, depth, "id=%d -> 0x%x" % (tid, tgt))
            while True:
                i, sub = self.expr(i, depth + 1)
                if sub == EX_AutoRtfmStopTransact:
                    break
        elif op == EX_AutoRtfmStopTransact:
            tid, i = self.i32(i)
            mode, i = self.u8(i)
            E(off, op, depth, "id=%d mode=%d" % (tid, mode))
        else:
            raise UnknownOpcode("opcode 0x%02X at bytecode offset 0x%x" % (op, off))
        return i, op

    def run(self):
        i = 0
        while i < self.n:
            i, op = self.expr(i, 0)
            if op == EX_EndOfScript:
                break
        return self.out


def disassemble(code, resolver=None):
    return Disassembler(code, resolver).run()


def render(instrs):
    return "\n".join("%06x %s%-26s %s" % (r["offset"], "  " * r["depth"], r["op"], r["text"])
                     for r in instrs)
