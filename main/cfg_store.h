#pragma once
#include <stdbool.h>

bool cfg_store_prepare(void);
bool cfg_store_confirmed(void);
void cfg_store_status(void);
bool cfg_store_command(const char *line);
bool cfg_store_take_reset_after_valid(void);
