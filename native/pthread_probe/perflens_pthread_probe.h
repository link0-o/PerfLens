/*
 * PerfLens native pthread runtime-lock probe private ABI.
 *
 * This header describes only the two passive ABI markers exported by the
 * LD_PRELOAD library.  Applications must not call into the probe directly;
 * the ordinary-user PerfLens launcher supplies a pre-opened evidence FD and
 * the probe interposes the supported glibc pthread entry points.
 */
#ifndef PERFLENS_PTHREAD_PROBE_H
#define PERFLENS_PTHREAD_PROBE_H

#include <stdint.h>

#ifndef PERFLENS_PTHREAD_PROBE_ABI_VERSION
#define PERFLENS_PTHREAD_PROBE_ABI_VERSION 1
#endif

#ifndef PERFLENS_PTHREAD_PROBE_PROTOCOL_VERSION
#define PERFLENS_PTHREAD_PROBE_PROTOCOL_VERSION "1.0"
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PERFLENS_PROBE_PUBLIC __attribute__((visibility("default")))
#else
#define PERFLENS_PROBE_PUBLIC
#endif

#ifdef __cplusplus
extern "C" {
#endif

PERFLENS_PROBE_PUBLIC extern const uint32_t perflens_pthread_probe_abi_version;
PERFLENS_PROBE_PUBLIC extern const char perflens_pthread_probe_protocol_version[];

#ifdef __cplusplus
}
#endif

#endif
