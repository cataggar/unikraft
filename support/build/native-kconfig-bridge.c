/* SPDX-License-Identifier: GPL-2.0 */

#include <stdlib.h>
#include "lkc.h"

#ifndef UK_KCONFIG_METADATA
#error "native metadata requires the metadata-specific Kconfig parser mode"
#endif

/* Inspect the same parsed model as conf, without reading or solving .config. */
void uk_kconfig_metadata(const char *path,
			void (*emit)(const char *, const char *))
{
	struct symbol *sym;
	int i;

	conf_parse(path);
	for_all_symbols(i, sym) {
		const char *type;

		if (!sym->name || (sym->flags & (SYMBOL_CONST | SYMBOL_CHOICE)))
			continue;
		switch (sym->type) {
		case S_BOOLEAN: type = "bool"; break;
		case S_TRISTATE: type = "tristate"; break;
		case S_STRING: type = "string"; break;
		case S_INT: type = "int"; break;
		case S_HEX: type = "hex"; break;
		default: continue;
		}
		emit(sym->name, type);
	}
}
