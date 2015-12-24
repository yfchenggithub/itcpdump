#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "log_dump.h"

void log_error(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_info(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_debug(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_warning(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}
