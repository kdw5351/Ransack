#pragma once

#include "common.hpp"

static void InitializeKeyTracking();
static void InstallKeyTrackingImageHooks(IMG img, const string &baseLower, bool trackedImage);
static void ShutdownKeyTracking();
