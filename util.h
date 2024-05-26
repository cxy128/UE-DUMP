#pragma once

#include "common.h"

bool InitSystemRoutineAddress();

unsigned __int64 GetSystemModuleBaseAddress(const char* ModuleName);
