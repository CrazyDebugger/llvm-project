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

struct ListState {
private:
  enum Kind { Created, Freed } K;
  ListState(Kind InK) : K(InK) { }

public:
  bool isCreated() const { return K == Created; }
  bool isFreed() const { return K == Freed; }

  static ListState getCreated() { return ListState(Created); }
  static ListState getFreed() { return ListState(Freed); }

  bool operator==(const ListState &X) const {
    return K == X.K;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
  }
};

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;

class SimpleListFreeChecker : public Checker<check::PreCall, check::PostCall> {
  CallDescription FreeFn;
  CallDescription LConsFn;
  CallDescription LConsIntFn;
  CallDescription LConsOidFn;
  CallDescription LAppendFn;
  CallDescription LAppendIntFn;
  CallDescription LAppendOidFn;
  CallDescription ListCopyFn;

  std::unique_ptr<BugType> FreeListWithPFreeBugType;

  void reportInconsistentListFree(SymbolRef FileDescSym,
                         const CallEvent &Call,
                         CheckerContext &C) const;

public:
  SimpleListFreeChecker();

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  /// Process pfree.
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
};

} // end anonymous namespace
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, ListState)

SimpleListFreeChecker::SimpleListFreeChecker()
  : FreeFn({"pfree"}), LConsFn({"lcons"}),
    LConsIntFn({"lcons_int"}), LConsOidFn({"lcons_oid"}),
    LAppendFn({"lappend"}), LAppendIntFn({"lappend_int"}),
    LAppendOidFn({"lappend_oid"}), ListCopyFn({"list_copy"}) {
  // Initialize the bug types.
  FreeListWithPFreeBugType.reset(
      new BugType(this, "pfree a list", "Postgres API Error"));
}

void SimpleListFreeChecker::checkPostCall(const CallEvent &Call,
					  CheckerContext &C) const {
  if (!Call.isGlobalCFunction())
    return;

  if (!LConsFn.matches(Call) && !LConsIntFn.matches(Call) &&
      !LConsOidFn.matches(Call) && !LAppendFn.matches(Call) &&
      !LAppendIntFn.matches(Call) && !LAppendOidFn.matches(Call) &&
      !LAppendOidFn.matches(Call) && !ListCopyFn.matches(Call))
    return;

  // Get the symbolic value corresponding to the file handle.
  SymbolRef ListPointer = Call.getReturnValue().getAsSymbol();
  if (!ListPointer)
    return;

  // Generate the next transition (an edge in the exploded graph).
  ProgramStateRef State = C.getState();
  State = State->set<StreamMap>(ListPointer, ListState::getCreated());
  C.addTransition(State);
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

  // Check if the stream has already been closed.
  ProgramStateRef State = C.getState();
  const ListState *LS = State->get<StreamMap>(ListPointer);
  if (LS && LS->isCreated()) {
    reportInconsistentListFree(ListPointer, Call, C);
    return;
  }
}

void SimpleListFreeChecker::reportInconsistentListFree(SymbolRef ListPointer,
                                            const CallEvent &Call,
                                            CheckerContext &C) const {
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
