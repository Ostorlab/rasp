// LLVM 18 new-PM pass. Explicit opt-in, fail closed on unsupported selected IR.
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/Local.h"
#include <cstdlib>
#include <map>
#include <set>
#include <string>

using namespace llvm;
namespace {
uint32_t next(uint32_t &state) {
    state ^= state << 13; state ^= state >> 17; state ^= state << 5;
    return state;
}
void validate(Function &function) {
    if (function.isDeclaration() || !function.getReturnType()->isIntegerTy() ||
        function.getReturnType()->getIntegerBitWidth() > 64 || function.isVarArg())
        report_fatal_error("rasp: selected function requires an integer return <=64 bits and fixed arguments");
    for (BasicBlock &block : function) {
        if (block.hasAddressTaken() || block.isEHPad()) report_fatal_error("rasp: unsupported block address or EH");
        if (!isa<BranchInst>(block.getTerminator()) && !isa<ReturnInst>(block.getTerminator()))
            report_fatal_error("rasp: unsupported terminator");
        for (Instruction &instruction : block) {
            if (auto *allocation = dyn_cast<AllocaInst>(&instruction))
                if (&block != &function.getEntryBlock() || !allocation->isStaticAlloca())
                    report_fatal_error("rasp: unsupported dynamic or non-entry alloca");
            if (auto *call = dyn_cast<CallBase>(&instruction)) {
                if (call->isInlineAsm() || call->hasFnAttr(Attribute::ReturnsTwice) || call->isConvergent())
                    report_fatal_error("rasp: unsupported asm, returns-twice or convergent call");
                if (auto *direct = dyn_cast<CallInst>(call))
                    if (direct->isMustTailCall()) report_fatal_error("rasp: unsupported musttail");
                if (Function *callee = call->getCalledFunction())
                    if (callee->getName().starts_with("llvm.stack") || callee->getName().starts_with("llvm.coro"))
                        report_fatal_error("rasp: unsupported stack or coroutine intrinsic");
            }
        }
    }
}
void mba(Function &function) {
    SmallVector<BinaryOperator *, 32> operations;
    for (Instruction &instruction : instructions(function))
        if (auto *operation = dyn_cast<BinaryOperator>(&instruction))
            if (operation->getType()->isIntegerTy() && operation->getType()->getIntegerBitWidth() > 1 &&
                operation->getType()->getIntegerBitWidth() <= 64 &&
                (operation->getOpcode() == Instruction::Add || operation->getOpcode() == Instruction::Xor))
                operations.push_back(operation);
    for (BinaryOperator *operation : operations) {
        IRBuilder<> builder(operation);
        Value *left = operation->getOperand(0), *right = operation->getOperand(1), *replacement;
        if (operation->getOpcode() == Instruction::Add)
            replacement = builder.CreateAdd(builder.CreateXor(left, right),
                                            builder.CreateShl(builder.CreateAnd(left, right), 1));
        else
            replacement = builder.CreateAnd(builder.CreateOr(left, right), builder.CreateNot(builder.CreateAnd(left, right)));
        operation->replaceAllUsesWith(replacement);
        operation->eraseFromParent();
    }
}
void harden(Function &function, uint32_t &seed) {
    mba(function);
    BasicBlock &entry = function.getEntryBlock();
    // Keep original static allocas in the entry so they dominate every dispatcher case.
    Instruction *split = &*entry.getFirstInsertionPt();
    while (isa<AllocaInst>(split)) split = split->getNextNode();
    BasicBlock *first = entry.splitBasicBlock(split, "rasp.first");
    Instruction *allocationPoint = entry.getTerminator();
    SmallVector<Instruction *, 32> spill;
    SmallVector<PHINode *, 16> phis;
    for (BasicBlock &block : function)
        for (Instruction &instruction : block) {
            if (auto *phi = dyn_cast<PHINode>(&instruction)) { phis.push_back(phi); continue; }
            if (instruction.getType()->isVoidTy() || isa<AllocaInst>(instruction)) continue;
            for (User *user : instruction.users())
                if (auto *consumer = dyn_cast<Instruction>(user))
                    if (consumer->getParent() != &block || isa<PHINode>(consumer)) { spill.push_back(&instruction); break; }
        }
    for (Instruction *instruction : spill) DemoteRegToStack(*instruction, false, allocationPoint);
    for (PHINode *phi : phis) DemotePHIToStack(phi, allocationPoint);
    LLVMContext &context = function.getContext();
    IRBuilder<> init(allocationPoint);
    Type *word = init.getInt32Ty();
    AllocaInst *state = init.CreateAlloca(word, nullptr, "rasp.state");
    std::map<BasicBlock *, uint32_t> labels;
    std::set<uint32_t> used;
    SmallVector<BasicBlock *, 16> blocks;
    for (BasicBlock &block : function) if (&block != &entry) {
        uint32_t label;
        do { label = next(seed); } while (!used.insert(label).second);
        labels[&block] = label; blocks.push_back(&block);
    }
    init.CreateStore(init.getInt32(labels[first]), state)->setVolatile(true);
    const char *probeName = std::getenv("RASP_PROBE_SYMBOL");
    if (!probeName || !*probeName) probeName = "rasp_guard_probe";
    auto guard = function.getParent()->getOrInsertFunction(probeName, init.getInt64Ty(), init.getInt64Ty());
    Value *probe = init.CreateCall(guard, {init.getInt64(next(seed))}, "rasp.probe");
    BasicBlock *dispatch = BasicBlock::Create(context, "rasp.dispatch", &function);
    BasicBlock *invalid = BasicBlock::Create(context, "rasp.invalid", &function);
    IRBuilder<>(invalid).CreateUnreachable();
    entry.getTerminator()->eraseFromParent();
    IRBuilder<>(&entry).CreateBr(dispatch);
    IRBuilder<> dispatcher(dispatch);
    auto *current = dispatcher.CreateLoad(word, state); current->setVolatile(true);
    auto *switcher = dispatcher.CreateSwitch(current, invalid, blocks.size());
    for (BasicBlock *block : blocks) switcher->addCase(dispatcher.getInt32(labels[block]), block);
    for (BasicBlock *block : blocks) {
        Instruction *terminator = block->getTerminator();
        IRBuilder<> builder(terminator);
        if (auto *branch = dyn_cast<BranchInst>(terminator)) {
            Value *destination = builder.getInt32(labels[branch->getSuccessor(0)]);
            if (branch->isConditional()) destination = builder.CreateSelect(branch->getCondition(), destination,
                                                                          builder.getInt32(labels[branch->getSuccessor(1)]));
            builder.CreateStore(destination, state)->setVolatile(true);
            builder.CreateBr(dispatch);
            terminator->eraseFromParent();
        } else if (auto *ret = dyn_cast<ReturnInst>(terminator)) {
            Value *folded = builder.CreateZExtOrTrunc(probe, function.getReturnType());
            ret->setOperand(0, builder.CreateXor(ret->getReturnValue(), folded));
        }
    }
    function.addFnAttr(Attribute::NoInline);
    if (verifyFunction(function, &errs())) report_fatal_error("rasp: transformed IR failed verification");
}
struct RaspPass : PassInfoMixin<RaspPass> {
    PreservedAnalyses run(Module &module, ModuleAnalysisManager &) {
        const char *selection = std::getenv("RASP_FUNCTIONS"), *seedText = std::getenv("RASP_SEED");
        if (!selection || !*selection || !seedText || !*seedText) report_fatal_error("rasp: RASP_FUNCTIONS and RASP_SEED required");
        uint32_t seed;
        if (StringRef(seedText).getAsInteger(10, seed) || seed == 0) report_fatal_error("rasp: seed must be a nonzero uint32");
        SmallVector<StringRef, 8> selected;
        StringRef(selection).split(selected, ',', -1, false);
        SmallVector<Function *, 8> functions;
        std::set<std::string> seen;
        for (StringRef name : selected) {
            if (!seen.insert(name.str()).second) report_fatal_error("rasp: duplicate selected function");
            Function *function = module.getFunction(name);
            if (!function) report_fatal_error("rasp: selected function not found");
            if (name == "rasp_guard_probe") report_fatal_error("rasp: cannot weave the probe itself");
            validate(*function); functions.push_back(function);
        }
        for (Function *function : functions) harden(*function, seed);
        return PreservedAnalyses::none();
    }
};
}
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "RaspPass", "1", [](PassBuilder &builder) {
        builder.registerPipelineParsingCallback([](StringRef name, ModulePassManager &manager, ArrayRef<PassBuilder::PipelineElement>) {
            if (name != "rasp-harden") return false;
            manager.addPass(RaspPass()); return true;
        });
    }};
}
