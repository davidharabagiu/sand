#ifndef SAND_API_SANDAPIDEFS_H_
#define SAND_API_SANDAPIDEFS_H_

#if defined(__GNUC__)
#define SAND_API_EXPORT_CTOR __attribute__((constructor))
#define SAND_API_EXPORT_DTOR __attribute((destructor))
#define SAND_API_EXPORT      __attribute__((visibility("default")))
#define SAND_API_IMPORT
#else  // Unsupported compiler
#define SAND_API_EXPORT
#define SAND_API_IMPORT
#endif  // defined(__GNUC__)

#ifdef SAND_BUILD_SHARED_LIB
#define SAND_API_CTOR SAND_API_EXPORT_CTOR
#define SAND_API_DTOR SAND_API_EXPORT_DTOR
#define SAND_API      SAND_API_EXPORT
#else
#define SAND_API_CTOR
#define SAND_API_DTOR
#define SAND_API SAND_API_IMPORT
#endif  // SAND_BUILD_SHARED_LIB

#endif  // SAND_API_SANDAPIDEFS_H_
