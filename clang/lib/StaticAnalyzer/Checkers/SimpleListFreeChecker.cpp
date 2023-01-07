#include "clang/Basic/IdentifierTable.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <utility>

using namespace clang;
using namespace ento;

namespace {
class SimpleListFreeChecker : public Checker<check::PreCall> {
  CallDescription FreeFn;
  std::unique_ptr<BugType> FreeListWithPFreeBugType;

  void reportInconsistentListFree(SymbolRef FileDescSym, const CallEvent &Call,
                                  CheckerContext &C) const;

public:
  SimpleListFreeChecker();
  /// Process pfree.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace

SimpleListFreeChecker::SimpleListFreeChecker() : FreeFn({"pfree"}) {
  // Initialize the bug types.
  FreeListWithPFreeBugType.reset(
      new BugType(this, "pfree a list", "Postgres API Error"));
}

void SimpleListFreeChecker::checkPreCall(const CallEvent &Call,
                                         CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  if (!FreeFn.matches(Call))
    return;

  // Get the symbolic value corresponding to the file handle.
  SymbolRef ListPointer = Call.getArgSVal(0).getAsSymbol();
  if (!ListPointer)
    return;

  // Check if the type of pfree() argument is List *.
  std::string TyName = ListPointer->getType()
                           ->getPointeeType()
                           .getUnqualifiedType()
                           .getAsString();
  if (TyName == "List") {
    reportInconsistentListFree(ListPointer, Call, C);
  }
}

void SimpleListFreeChecker::reportInconsistentListFree(
    SymbolRef ListPointer, const CallEvent &Call, CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = std::make_unique<PathSensitiveBugReport>(
      *FreeListWithPFreeBugType, "Freeing a (List *) with pfree", ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(ListPointer);
  C.emitReport(std::move(R));
}

void ento::registerSimpleListFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<SimpleListFreeChecker>();
}

// This checker should be enabled regardless of how language options are set.
bool ento::shouldRegisterSimpleListFreeChecker(const CheckerManager &mgr) {
  return true;
}
