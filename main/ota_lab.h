#ifndef OTA_LAB_H
#define OTA_LAB_H

#include <stdbool.h>

/* UART ownership remains with main.c. Commands are not echoed by this module. */
void ota_lab_init(void);
bool ota_lab_command(const char *line);
/* Called before MARK_VALID. Reads the staged signed-artifact identity without
 * starting networking; compiled schema/version must match the signed contract.
 */
bool ota_lab_trial_health(void);

/* LAB_FAULT_PROFILE builds additionally expose explicit lab-* diagnostics via
 * ota_lab_command. Default production builds have neither local TLS origins
 * nor the public laboratory CA nor checkpoint-corruption/clock hooks.
 */

#endif
