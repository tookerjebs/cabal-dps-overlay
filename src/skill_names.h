#ifndef PLAYCABAL_WIRE_SKILL_NAMES_H
#define PLAYCABAL_WIRE_SKILL_NAMES_H

#include <stdint.h>

/* English name from decoded cabal_msg.xml, or NULL if unknown. */
const char *pw_skill_name(uint32_t id);

#endif
