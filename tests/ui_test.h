#ifndef UI_TEST_H
#define UI_TEST_H

/* Minimal test helpers: no external framework. A failed CHECK prints the
 * location and counts the failure; main() returns non-zero if any failed.
 */

#include <stdio.h>
#include <string.h>

static int g_test_failures = 0;
static int g_test_checks = 0;

#define CHECK(cond) do { \
	g_test_checks++; \
	if (!(cond)) { \
		g_test_failures++; \
		fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

#define CHECK_INT(a, b) do { \
	long long _a = (long long)(a), _b = (long long)(b); \
	g_test_checks++; \
	if (_a != _b) { \
		g_test_failures++; \
		fprintf(stderr, "%s:%d: CHECK_INT failed: %s == %lld, expected %s == %lld\n", \
			__FILE__, __LINE__, #a, _a, #b, _b); \
	} \
} while (0)

#define CHECK_STR(a, b) do { \
	const char *_a = (a), *_b = (b); \
	g_test_checks++; \
	if (strcmp(_a, _b) != 0) { \
		g_test_failures++; \
		fprintf(stderr, "%s:%d: CHECK_STR failed:\n  got      '%s'\n  expected '%s'\n", \
			__FILE__, __LINE__, _a, _b); \
	} \
} while (0)

#define RUN(fn) do { fn(); } while (0)

#define TEST_RESULT() ( \
	fprintf(stderr, "%d checks, %d failures\n", g_test_checks, g_test_failures), \
	g_test_failures ? 1 : 0)

#endif /* UI_TEST_H */
