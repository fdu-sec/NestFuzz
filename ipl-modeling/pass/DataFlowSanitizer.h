//===- DataFlowSanitizer.h - dynamic data flow analysis -------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//


#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include <string>
#include <vector>

namespace llvm{

struct DFSanPass
    : public llvm::PassInfoMixin<DFSanPass> {
private:
  std::vector<std::string> ABIListFiles;

public:
  DFSanPass(
      const std::vector<std::string> &ABIListFiles = std::vector<std::string>())
      : ABIListFiles(ABIListFiles) {}
  llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

}