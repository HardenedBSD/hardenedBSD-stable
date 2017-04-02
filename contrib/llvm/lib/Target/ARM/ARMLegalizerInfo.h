//===- ARMLegalizerInfo ------------------------------------------*- C++ -*-==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
/// This file declares the targeting of the Machinelegalizer class for ARM.
/// \todo This should be generated by TableGen.
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_ARM_ARMMACHINELEGALIZER_H
#define LLVM_LIB_TARGET_ARM_ARMMACHINELEGALIZER_H

#include "llvm/CodeGen/GlobalISel/LegalizerInfo.h"

namespace llvm {

class LLVMContext;

/// This class provides the information for the target register banks.
class ARMLegalizerInfo : public LegalizerInfo {
public:
  ARMLegalizerInfo();
};
} // End llvm namespace.
#endif
