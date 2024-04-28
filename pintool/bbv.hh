#pragma once

#include <unordered_map>

#include "pin.H"

class BBVBlock {
  public:
    using Count = unsigned;
    
    void reset() { _hitCount = 0; }
    void increment() { ++_hitCount; }
    Count hitCount() const { return _hitCount; }
  private:
    Count _hitCount;
};

class BBVTrace {
  public:
    BBVBlock *block(ADDRINT addr);
    void reset();
  private:
    std::unordered_map<ADDRINT, BBVBlock> blocks;
};
