#pragma once

#include "common.hpp"
#include "loop_detection.hpp"

static bool CaptureLoopArtifacts(UINT32 captureId, ThreadState *threadState,
                                 const LoopKey &key,
                                 const ThreadLoopState &loopState);
