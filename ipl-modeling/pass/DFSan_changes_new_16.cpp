diff --git a/DataFlowSanitizer.cpp b/DFSan_16.cpp
index fbf0280..e9614b4 100644
--- a/DataFlowSanitizer.cpp
+++ b/DFSan_16.cpp
@@ -59,9 +59,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "llvm/Transforms/IPO/PassManagerBuilder.h"
-#include "DataFlowSanitizer.h"
-#include "llvm/IR/LegacyPassManager.h"
+#include "llvm/Transforms/Instrumentation/DataFlowSanitizer.h"
 #include "llvm/ADT/DenseMap.h"
 #include "llvm/ADT/DenseSet.h"
 #include "llvm/ADT/DepthFirstIterator.h"
@@ -109,10 +107,6 @@
 #include "llvm/Transforms/Instrumentation.h"
 #include "llvm/Transforms/Utils/BasicBlockUtils.h"
 #include "llvm/Transforms/Utils/Local.h"
-#include "llvm/Passes/OptimizationLevel.h"
-#include "llvm/Passes/PassPlugin.h"
-#include "llvm/Passes/PassBuilder.h"
-#include "llvm/IR/PassManager.h"
 #include <algorithm>
 #include <cassert>
 #include <cstddef>
@@ -142,7 +136,7 @@ static const unsigned RetvalTLSSize = 800;
 // we have unfortunately encountered too much code (including Clang itself;
 // see PR14291) which performs misaligned access.
 static cl::opt<bool> ClPreserveAlignment(
-    "chunk-dfsan-preserve-alignment",
+    "dfsan-preserve-alignment",
     cl::desc("respect alignment requirements provided by input IR"), cl::Hidden,
     cl::init(false));
 
@@ -163,16 +157,14 @@ static cl::opt<bool> ClPreserveAlignment(
 // Functions should never be labelled with both "force_zero_labels" and
 // "uninstrumented" or any of the unistrumented wrapper kinds.
 static cl::list<std::string> ClABIListFiles(
-    "chunk-dfsan-abilist",
+    "dfsan-abilist",
     cl::desc("File listing native ABI functions and how the pass treats them"),
-    cl::Hidden,
-    cl::value_desc("filename"),
-    cl::ZeroOrMore);
+    cl::Hidden);
 
 // Controls whether the pass includes or ignores the labels of pointers in load
 // instructions.
 static cl::opt<bool> ClCombinePointerLabelsOnLoad(
-    "chunk-dfsan-combine-pointer-labels-on-load",
+    "dfsan-combine-pointer-labels-on-load",
     cl::desc("Combine the label of the pointer with the label of the data when "
              "loading from memory."),
     cl::Hidden, cl::init(true));
@@ -180,21 +172,21 @@ static cl::opt<bool> ClCombinePointerLabelsOnLoad(
 // Controls whether the pass includes or ignores the labels of pointers in
 // stores instructions.
 static cl::opt<bool> ClCombinePointerLabelsOnStore(
-    "chunk-dfsan-combine-pointer-labels-on-store",
+    "dfsan-combine-pointer-labels-on-store",
     cl::desc("Combine the label of the pointer with the label of the data when "
              "storing in memory."),
     cl::Hidden, cl::init(false));
 
 // Controls whether the pass propagates labels of offsets in GEP instructions.
 static cl::opt<bool> ClCombineOffsetLabelsOnGEP(
-    "chunk-dfsan-combine-offset-labels-on-gep",
+    "dfsan-combine-offset-labels-on-gep",
     cl::desc(
         "Combine the label of the offset with the label of the pointer when "
         "doing pointer arithmetic."),
     cl::Hidden, cl::init(true));
 
 static cl::list<std::string> ClCombineTaintLookupTables(
-    "chunk-dfsan-combine-taint-lookup-table",
+    "dfsan-combine-taint-lookup-table",
     cl::desc(
         "When dfsan-combine-offset-labels-on-gep and/or "
         "dfsan-combine-pointer-labels-on-load are false, this flag can "
@@ -203,7 +195,7 @@ static cl::list<std::string> ClCombineTaintLookupTables(
     cl::Hidden);
 
 static cl::opt<bool> ClDebugNonzeroLabels(
-    "chunk-dfsan-debug-nonzero-labels",
+    "dfsan-debug-nonzero-labels",
     cl::desc("Insert calls to __dfsan_nonzero_label on observing a parameter, "
              "load or return with a nonzero label"),
     cl::Hidden);
@@ -219,7 +211,7 @@ static cl::opt<bool> ClDebugNonzeroLabels(
 //   void __dfsan_mem_transfer_callback(dfsan_label *Start, size_t Len);
 //   void __dfsan_cmp_callback(dfsan_label CombinedLabel);
 static cl::opt<bool> ClEventCallbacks(
-    "chunk-dfsan-event-callbacks",
+    "dfsan-event-callbacks",
     cl::desc("Insert calls to __dfsan_*_callback functions on data events."),
     cl::Hidden, cl::init(false));
 
@@ -227,7 +219,7 @@ static cl::opt<bool> ClEventCallbacks(
 // conditional branch, switch, select.
 // This must be true for dfsan_set_conditional_callback() to have effect.
 static cl::opt<bool> ClConditionalCallbacks(
-    "chunk-dfsan-conditional-callbacks",
+    "dfsan-conditional-callbacks",
     cl::desc("Insert calls to callback functions on conditionals."), cl::Hidden,
     cl::init(false));
 
@@ -235,20 +227,20 @@ static cl::opt<bool> ClConditionalCallbacks(
 // either via function arguments and loads.
 // This must be true for dfsan_set_reaches_function_callback() to have effect.
 static cl::opt<bool> ClReachesFunctionCallbacks(
-    "chunk-dfsan-reaches-function-callbacks",
+    "dfsan-reaches-function-callbacks",
     cl::desc("Insert calls to callback functions on data reaching a function."),
     cl::Hidden, cl::init(false));
 
 // Controls whether the pass tracks the control flow of select instructions.
 static cl::opt<bool> ClTrackSelectControlFlow(
-    "chunk-dfsan-track-select-control-flow",
+    "dfsan-track-select-control-flow",
     cl::desc("Propagate labels from condition values of select instructions "
              "to results."),
     cl::Hidden, cl::init(true));
 
 // TODO: This default value follows MSan. DFSan may use a different value.
 static cl::opt<int> ClInstrumentWithCallThreshold(
-    "chunk-dfsan-instrument-with-call-threshold",
+    "dfsan-instrument-with-call-threshold",
     cl::desc("If the function being instrumented requires more than "
              "this number of origin stores, use callbacks instead of "
              "inline checks (-1 means never use callbacks)."),
@@ -259,12 +251,12 @@ static cl::opt<int> ClInstrumentWithCallThreshold(
 // * 1: track origins at memory store operations.
 // * 2: track origins at memory load and store operations.
 //      TODO: track callsites.
-static cl::opt<int> ClTrackOrigins("chunk-dfsan-track-origins",
+static cl::opt<int> ClTrackOrigins("dfsan-track-origins",
                                    cl::desc("Track origins of labels"),
                                    cl::Hidden, cl::init(0));
 
 static cl::opt<bool> ClIgnorePersonalityRoutine(
-    "chunk-dfsan-ignore-personality-routine",
+    "dfsan-ignore-personality-routine",
     cl::desc("If a personality routine is marked uninstrumented from the ABI "
              "list, do not create a wrapper for it."),
     cl::Hidden, cl::init(false));
@@ -419,7 +411,7 @@ class DataFlowSanitizer {
   friend struct DFSanFunction;
   friend class DFSanVisitor;
 
-  enum { ShadowWidthBits = 32, ShadowWidthBytes = ShadowWidthBits / 8 };
+  enum { ShadowWidthBits = 8, ShadowWidthBytes = ShadowWidthBits / 8 };
 
   enum { OriginWidthBits = 32, OriginWidthBytes = OriginWidthBits / 8 };
 
@@ -456,7 +448,6 @@ class DataFlowSanitizer {
   IntegerType *PrimitiveShadowTy;
   PointerType *PrimitiveShadowPtrTy;
   IntegerType *IntptrTy;
-  IntegerType *Int8Ty;
   ConstantInt *ZeroPrimitiveShadow;
   Constant *ArgTLS;
   ArrayType *ArgOriginTLSTy;
@@ -470,19 +461,6 @@ class DataFlowSanitizer {
   FunctionType *DFSanSetLabelFnTy;
   FunctionType *DFSanNonzeroLabelFnTy;
   FunctionType *DFSanVarargWrapperFnTy;
-  
-  // add start
-
-  FunctionType *DFSanCombineAndFnTy;
-  FunctionType *DFSanInferShapeFnTy;
-  FunctionType *DFSanUnionFnTy;
-  FunctionCallee DFSanUnionFn;
-  FunctionCallee DFSanMarkSignedFn;
-  FunctionCallee DFSanCombineAndFn;
-  FunctionCallee DFSanInferShapeFn;
-
-  // add end
-
   FunctionType *DFSanConditionalCallbackFnTy;
   FunctionType *DFSanConditionalCallbackOriginFnTy;
   FunctionType *DFSanReachesFunctionCallbackFnTy;
@@ -524,9 +502,6 @@ class DataFlowSanitizer {
   DenseMap<Value *, Function *> UnwrappedFnMap;
   AttributeMask ReadOnlyNoneAttrs;
   StringSet<> CombineTaintLookupTableNames;
-  
-  // std::vector<std::string> ABIListFiles;
-  // DFSanABIList ABIList;
 
   /// Memory map parameters used in calculation mapping application addresses
   /// to shadow addresses and origin addresses.
@@ -587,43 +562,12 @@ class DataFlowSanitizer {
   const uint64_t NumOfElementsInArgOrgTLS = ArgTLSSize / OriginWidthBytes;
 
 public:
-  DataFlowSanitizer(const std::vector<std::string> &ABIListFiles);
-  // PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
-  bool runImpl(Module &M, llvm::function_ref<TargetLibraryInfo &(Function &)> GetTLI);
-  /*
-  DataFlowSanitizer(const std::vector<std::string> &ABIListFiles) {}
-  DataFlowSanitizer(const std::vector<std::string> &ABIListFiles) 
-    : ABIListFiles(ABIListFiles) {
-    std::vector<std::string> AllABIListFiles(std::move(this->ABIListFiles));
-    llvm::append_range(AllABIListFiles, ClABIListFiles);
-    // FIXME: should we propagate vfs::FileSystem to this constructor?
-    ABIList.set(SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));
-
-    for (StringRef v : ClCombineTaintLookupTables)
-      CombineTaintLookupTableNames.insert(v);
-  };
-  
-  DataFlowSanitizer() {
-    // Read ABI list files from command line arguments
-    for (const auto &File : ClABIListFiles) {
-        // Load and parse the ABI list file
-        // Assuming SpecialCaseList is the mechanism you still want to use
-        ABILists.push_back(SpecialCaseList::createOrDie({File}, *vfs::getRealFileSystem()));
-    }
-  }
-
-  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
-  bool runImpl(Module &M, function_ref<TargetLibraryInfo &(Function &)> GetTLI);
-  
   DataFlowSanitizer(const std::vector<std::string> &ABIListFiles);
 
   bool runImpl(Module &M,
                llvm::function_ref<TargetLibraryInfo &(Function &)> GetTLI);
-  */
-
 };
 
-
 struct DFSanFunction {
   DataFlowSanitizer &DFS;
   Function *F;
@@ -855,7 +799,6 @@ public:
   void visitLibAtomicStore(CallBase &CB);
   void visitLibAtomicExchange(CallBase &CB);
   void visitLibAtomicCompareExchange(CallBase &CB);
-  // vital
   void visitCallBase(CallBase &CB);
   void visitPHINode(PHINode &PN);
   void visitExtractElementInst(ExtractElementInst &I);
@@ -889,7 +832,6 @@ private:
   Value *makeAddReleaseOrderingTable(IRBuilder<> &IRB);
 };
 
-// llvm16新添加的
 bool LibAtomicFunction(const Function &F) {
   // This is a bit of a hack because TargetLibraryInfo is a function pass.
   // The DFSan pass would need to be refactored to be function pass oriented
@@ -912,21 +854,6 @@ bool LibAtomicFunction(const Function &F) {
 
 } // end anonymous namespace
 
-
-DataFlowSanitizer::DataFlowSanitizer(
-    const std::vector<std::string> &ABIListFiles) {
-  std::vector<std::string> AllABIListFiles(std::move(ABIListFiles));
-  llvm::append_range(AllABIListFiles, ClABIListFiles);
-  // FIXME: should we propagate vfs::FileSystem to this constructor?
-  ABIList.set(
-      SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));
-
-  for (StringRef v : ClCombineTaintLookupTables)
-    CombineTaintLookupTableNames.insert(v);
-}
-
-// 缺少initial
-/*
 DataFlowSanitizer::DataFlowSanitizer(
     const std::vector<std::string> &ABIListFiles) {
   std::vector<std::string> AllABIListFiles(std::move(ABIListFiles));
@@ -938,7 +865,6 @@ DataFlowSanitizer::DataFlowSanitizer(
   for (StringRef v : ClCombineTaintLookupTables)
     CombineTaintLookupTableNames.insert(v);
 }
-*/
 
 TransformedFunction DataFlowSanitizer::getCustomFunctionType(FunctionType *T) {
   SmallVector<Type *, 4> ArgTypes;
@@ -1214,16 +1140,9 @@ bool DataFlowSanitizer::initializeModule(Module &M) {
   PrimitiveShadowTy = IntegerType::get(*Ctx, ShadowWidthBits);
   PrimitiveShadowPtrTy = PointerType::getUnqual(PrimitiveShadowTy);
   IntptrTy = DL.getIntPtrType(*Ctx);
-  Int8Ty = IntegerType::getInt8Ty(*Ctx);
   ZeroPrimitiveShadow = ConstantInt::getSigned(PrimitiveShadowTy, 0);
   ZeroOrigin = ConstantInt::getSigned(OriginTy, 0);
 
-  // add start
-  Type *DFSanUnionArgs[2] = {PrimitiveShadowTy, PrimitiveShadowTy};
-  DFSanUnionFnTy = FunctionType::get(PrimitiveShadowTy, DFSanUnionArgs,
-                                         /*isVarArg=*/false);
-  // add end
-
   Type *DFSanUnionLoadArgs[2] = {PrimitiveShadowPtrTy, IntptrTy};
   DFSanUnionLoadFnTy = FunctionType::get(PrimitiveShadowTy, DFSanUnionLoadArgs,
                                          /*isVarArg=*/false);
@@ -1245,16 +1164,6 @@ bool DataFlowSanitizer::initializeModule(Module &M) {
                                             /*isVarArg=*/false);
   DFSanVarargWrapperFnTy = FunctionType::get(
       Type::getVoidTy(*Ctx), Type::getInt8PtrTy(*Ctx), /*isVarArg=*/false);
-
-  // add start & fix
-  DFSanCombineAndFnTy =
-      FunctionType::get(Type::getVoidTy(*Ctx), PrimitiveShadowPtrTy, /*isVarArg=*/false);
-
-  Type *DFSanInferShapeArgs[3] = {PrimitiveShadowTy, PrimitiveShadowTy, PrimitiveShadowTy};
-  DFSanInferShapeFnTy = FunctionType::get(
-      Type::getVoidTy(*Ctx), DFSanInferShapeArgs, /*isVarArg=*/false);
-  // add end
-
   DFSanConditionalCallbackFnTy =
       FunctionType::get(Type::getVoidTy(*Ctx), PrimitiveShadowTy,
                         /*isVarArg=*/false);
@@ -1386,15 +1295,8 @@ DataFlowSanitizer::buildWrapperFunction(Function *F, StringRef NewFName,
       AttributeFuncs::typeIncompatible(NewFT->getReturnType()));
 
   BasicBlock *BB = BasicBlock::Create(*Ctx, "entry", NewF);
-  // if (F->isVarArg()) {
-  //   NewF->removeFnAttr("split-stack");
-  
-  // add start & fix
-  if (F->isVarArg() && getWrapperKind(F) != WK_Discard) {
-    // LLVM_REMOVE_ATTRIBUTE(NewF, "split-stack"); 
+  if (F->isVarArg()) {
     NewF->removeFnAttr("split-stack");
-  // add end
-  
     CallInst::Create(DFSanVarargWrapperFn,
                      IRBuilder<>(BB).CreateGlobalStringPtr(F->getName()), "",
                      BB);
@@ -1416,63 +1318,6 @@ DataFlowSanitizer::buildWrapperFunction(Function *F, StringRef NewFName,
 // Initialize DataFlowSanitizer runtime functions and declare them in the module
 void DataFlowSanitizer::initializeRuntimeFunctions(Module &M) {
   LLVMContext &C = M.getContext();
-
-  // add start
-  {
-    AttributeList AL;
-    AL = AL.addFnAttribute(C, Attribute::NoUnwind);
-    AL = AL.addFnAttribute(C, Attribute::Memory);
-    AL = AL.addRetAttribute(C, Attribute::ZExt);
-    AL = AL.addParamAttribute(C, 0, Attribute::ZExt);
-    AL = AL.addParamAttribute(C, 1, Attribute::ZExt);
-    DFSanMarkSignedFn =
-      Mod->getOrInsertFunction("dfsan_mark_signed", DFSanUnionFnTy, AL);
-  }
-
-  // find & ops.
-  {
-    AttributeList AL;
-    AL = AL.addFnAttribute(C, Attribute::NoUnwind);
-    AL = AL.addFnAttribute(C, Attribute::Memory);
-    // AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);                  
-    DFSanCombineAndFn =
-      Mod->getOrInsertFunction("dfsan_combine_and_ins", DFSanCombineAndFnTy, AL);
-  }
-
-  {
-    AttributeList AL;
-    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
-    AL = AL.addFnAttribute(M.getContext(), Attribute::Memory);
-    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 2, Attribute::ZExt);
-    DFSanInferShapeFn = Mod->getOrInsertFunction("dfsan_infer_shape_in_math_op",
-                                               DFSanInferShapeFnTy, AL);
-  }
-
-  {
-    AttributeList AL;
-    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
-    AL = AL.addFnAttribute(M.getContext(), Attribute::Memory);
-    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
-    DFSanUnionFn =
-        Mod->getOrInsertFunction("__dfsan_union", DFSanUnionFnTy, AL);
-  }
-  /*
-  {
-    AttributeList AL;
-    AL = AL.addFnAttribute(M.getContext(), Attribute::NoUnwind);
-    AL = AL.addFnAttribute(M.getContext(), Attribute::ReadNone);
-    AL = AL.addRetAttribute(M.getContext(), Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 0, Attribute::ZExt);
-    AL = AL.addParamAttribute(M.getContext(), 1, Attribute::ZExt);
-    DFSanCheckedUnionFn =
-        Mod->getOrInsertFunction("dfsan_union", DFSanUnionFnTy, AL);
-  }*/
-  // add end
-
   {
     AttributeList AL;
     AL = AL.addFnAttribute(C, Attribute::NoUnwind);
@@ -1553,16 +1398,6 @@ void DataFlowSanitizer::initializeRuntimeFunctions(Module &M) {
       DFSanNonzeroLabelFn.getCallee()->stripPointerCasts());
   DFSanRuntimeFunctions.insert(
       DFSanVarargWrapperFn.getCallee()->stripPointerCasts());
-  
-  // add start
-  DFSanRuntimeFunctions.insert(
-      DFSanMarkSignedFn.getCallee()->stripPointerCasts());
-  DFSanRuntimeFunctions.insert(
-      DFSanCombineAndFn.getCallee()->stripPointerCasts());
-  DFSanRuntimeFunctions.insert(
-      DFSanInferShapeFn.getCallee()->stripPointerCasts());
-  // add end
-  
   DFSanRuntimeFunctions.insert(
       DFSanLoadCallbackFn.getCallee()->stripPointerCasts());
   DFSanRuntimeFunctions.insert(
@@ -2122,105 +1957,6 @@ Value *DFSanFunction::combineShadowsThenConvert(Type *T, Value *V1, Value *V2,
 // Generates IR to compute the union of the two given shadows, inserting it
 // before Pos. The combined value is with primitive type.
 Value *DFSanFunction::combineShadows(Value *V1, Value *V2, Instruction *Pos) {
-  // add start
-  // https://stackoverflow.com/questions/30519005/how-to-distinguish-signed-and-unsigned-integer-in-llvm
-  // http://nondot.org/sabre/LLVMNotes/TypeSystemChanges.txt
-  bool is_signed = false;
-  switch (Pos->getOpcode()) {
-  // case Instruction::SExt: // in combine operandshadows..
-  case Instruction::SDiv:
-  case Instruction::SRem:
-  case Instruction::AShr:
-    is_signed = true;
-    break;
-  case Instruction::And:
-    if (Pos->getNumOperands() == 2) {
-      Value *Arg1 = Pos->getOperand(0);
-      Value *Arg2 = Pos->getOperand(1);
-      if (Arg1->getType()->isIntegerTy() && Arg2->getType()->isIntegerTy()) {
-        IRBuilder<> IRB(Pos);
-        
-        // add start & fix
-        if (isa<ConstantInt>(Arg1) && !DFS.isZeroShadow(V2)) { // Constant
-          CallInst *Call = IRB.CreateCall(DFS.DFSanCombineAndFn, {V2});
-          Call->addParamAttr(0, Attribute::ZExt);
-        } else if (isa<ConstantInt>(Arg2) && !DFS.isZeroShadow(V1)) {
-          CallInst *Call = IRB.CreateCall(DFS.DFSanCombineAndFn, {V1});
-          Call->addParamAttr(0, Attribute::ZExt);
-        }
-        // add end
-        
-        /*
-        if (isa<ConstantInt>(Arg1) && V2 != DFS.ZeroShadow) { // Constant
-          CallInst *Call = IRB.CreateCall(DFS.DFSanCombineAndFn, {V2});
-          Call->addAttribute(0, Attribute::ZExt);
-        } else if (isa<ConstantInt>(Arg2) && V1 != DFS.ZeroShadow) {
-          CallInst *Call = IRB.CreateCall(DFS.DFSanCombineAndFn, {V1});
-          Call->addAttribute(0, Attribute::ZExt);
-        }
-        */
-      }
-    }
-    break;
-  default:
-    // LangOptions::SOB_Undefined && bits < 32(i16 will be optimization to
-    // remove usw) see
-    // https://github.com/llvm-mirror/clang/blob/release_40/lib/CodeGen/CGExprScalar.cpp
-    // detect nsw attribute: which the most important thing to mark signed
-    // integer.
-    if (OverflowingBinaryOperator *op =
-            dyn_cast<OverflowingBinaryOperator>(Pos)) {
-      if (op->hasNoSignedWrap() && !op->hasNoUnsignedWrap())
-        is_signed = true;
-    } else if (CmpInst *op = dyn_cast<CmpInst>(Pos)) {
-      if (op->isSigned())
-        is_signed = true;
-    }
-    break;
-  }
-
-  if (is_signed) {
-    IRBuilder<> IRB(Pos);
-    CallInst *Call = IRB.CreateCall(DFS.DFSanMarkSignedFn, {V1, V2});
-    /*
-    Call->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
-    Call->addAttribute(0, Attribute::ZExt);
-    Call->addAttribute(1, Attribute::ZExt);
-    */
-    // add start & fix
-    Call->addRetAttr(Attribute::ZExt);
-    Call->addParamAttr(0, Attribute::ZExt);
-    Call->addParamAttr(1, Attribute::ZExt);
-    // add end
-  }
-
-  switch (Pos->getOpcode()) {
-  case Instruction::Add:
-  case Instruction::Sub:
-  case Instruction::Mul:
-  case Instruction::UDiv:
-  case Instruction::SDiv:
-  case Instruction::SRem:
-    // case Instruction::Shl:
-    // case Instruction::AShr:
-    // case Instruction::LShr:
-    IRBuilder<> IRB(Pos);
-    Value *Arg1 = Pos->getOperand(0);
-    int num_bits = Arg1->getType()->getScalarSizeInBits();
-    int num_bytes = num_bits / 8;
-    if (num_bytes > 0 && num_bits % 8 == 0) {
-      // fix
-      Value *SizeArg = ConstantInt::get(DFS.PrimitiveShadowTy, num_bytes);
-      CallInst *Call = IRB.CreateCall(DFS.DFSanInferShapeFn, {V1, V2, SizeArg});
-      Call->addParamAttr(1, Attribute::ZExt);
-      Call->addParamAttr(2, Attribute::ZExt);
-    }
-    break;
-  }
-  // add end
-  
-
-
   if (DFS.isZeroShadow(V1))
     return collapseToPrimitiveShadow(V2, Pos);
   if (DFS.isZeroShadow(V2))
@@ -2286,23 +2022,6 @@ Value *DFSanFunction::combineOperandShadows(Instruction *Inst) {
     return DFS.getZeroShadow(Inst);
 
   Value *Shadow = getShadow(Inst->getOperand(0));
-  if (Inst->getOpcode() == Instruction::SExt) {
-    IRBuilder<> IRB(Inst);
-    // add start & fix
-    CallInst *Call =
-        IRB.CreateCall(DFS.DFSanMarkSignedFn, {Shadow, DFS.ZeroPrimitiveShadow});
-    Call->addRetAttr(Attribute::ZExt);
-    Call->addParamAttr(0, Attribute::ZExt);
-    Call->addParamAttr(1, Attribute::ZExt);
-    // add end
-    /*
-    CallInst *Call =
-        IRB.CreateCall(DFS.DFSanMarkSignedFn, {Shadow, DFS.ZeroPrimitiveShadow});
-    Call->addAttribute(AttributeList::ReturnIndex, Attribute::ZExt);
-    Call->addAttribute(0, Attribute::ZExt);
-    Call->addAttribute(1, Attribute::ZExt);
-    */
-  }
   for (unsigned I = 1, N = Inst->getNumOperands(); I < N; ++I)
     Shadow = combineShadows(Shadow, getShadow(Inst->getOperand(I)), Inst);
 
@@ -2573,16 +2292,16 @@ std::pair<Value *, Value *> DFSanFunction::loadShadowOriginSansLoadTracking(
     LI->setAlignment(ShadowAlign);
     return {LI, Origin};
   }
-  // case 2: {
-  //   IRBuilder<> IRB(Pos);
-  //   Value *ShadowAddr1 = IRB.CreateGEP(DFS.PrimitiveShadowTy, ShadowAddr,
-  //                                      ConstantInt::get(DFS.IntptrTy, 1));
-  //   Value *Load =
-  //       IRB.CreateAlignedLoad(DFS.PrimitiveShadowTy, ShadowAddr, ShadowAlign);
-  //   Value *Load1 =
-  //       IRB.CreateAlignedLoad(DFS.PrimitiveShadowTy, ShadowAddr1, ShadowAlign);
-  //   return {combineShadows(Load, Load1, Pos), Origin};
-  // }
+  case 2: {
+    IRBuilder<> IRB(Pos);
+    Value *ShadowAddr1 = IRB.CreateGEP(DFS.PrimitiveShadowTy, ShadowAddr,
+                                       ConstantInt::get(DFS.IntptrTy, 1));
+    Value *Load =
+        IRB.CreateAlignedLoad(DFS.PrimitiveShadowTy, ShadowAddr, ShadowAlign);
+    Value *Load1 =
+        IRB.CreateAlignedLoad(DFS.PrimitiveShadowTy, ShadowAddr1, ShadowAlign);
+    return {combineShadows(Load, Load1, Pos), Origin};
+  }
   }
   bool HasSizeForFastPath = DFS.hasLoadSizeForFastPath(Size);
 
@@ -3748,41 +3467,20 @@ void DFSanVisitor::visitPHINode(PHINode &PN) {
   DFSF.PHIFixups.push_back({&PN, ShadowPN, OriginPN});
 }
 
-PreservedAnalyses DFSanPass::run(Module &M,
+PreservedAnalyses DataFlowSanitizerPass::run(Module &M,
                                              ModuleAnalysisManager &AM) {
-  errs() << "DFSan run!\n";
   auto GetTLI = [&](Function &F) -> TargetLibraryInfo & {
     auto &FAM =
         AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
     return FAM.getResult<TargetLibraryAnalysis>(F);
   };
-  if (DataFlowSanitizer(ABIListFiles).runImpl(M, GetTLI))
-    return PreservedAnalyses::none();
-  return PreservedAnalyses::all();
-}
-
-
-llvm::PassPluginLibraryInfo getDFSanPassPluginInfo() {
-  return {LLVM_PLUGIN_API_VERSION, "DFSanPass", LLVM_VERSION_STRING,
-          [](PassBuilder &PB) {
-            PB.registerOptimizerLastEPCallback(
-                [](llvm::ModulePassManager &MPM,
-                   llvm::OptimizationLevel Level) {
-                  MPM.addPass(DFSanPass());
-                });
-            PB.registerPipelineParsingCallback(
-                [](StringRef Name, llvm::ModulePassManager &MPM,
-                   ArrayRef<llvm::PassBuilder::PipelineElement>) {
-                  if (Name == "dfsan-pass") {
-                    MPM.addPass(DFSanPass());
-                    return true;
-                  }
-                  return false;
-                });
-          }};
-}
-
-extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
-llvmGetPassPluginInfo() {
-  return getDFSanPassPluginInfo();
-}
\ No newline at end of file
+  if (!DataFlowSanitizer(ABIListFiles).runImpl(M, GetTLI))
+    return PreservedAnalyses::all();
+
+  PreservedAnalyses PA = PreservedAnalyses::none();
+  // GlobalsAA is considered stateless and does not get invalidated unless
+  // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
+  // make changes that require GlobalsAA to be invalidated.
+  PA.abandon<GlobalsAA>();
+  return PA;
+}
