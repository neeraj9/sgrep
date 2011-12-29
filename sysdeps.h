/*
	System: Structured text retrieval tool sgrep.
	Module: sysdeps.h
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: header file for system dependent stuff.
	Version history: Original version February 1998 by JJ
	Copyright: University of Helsinki, Dept. of Computer Science
		   Distributed under GNU General Public Lisence
		   See file COPYING for details
*/

#ifdef HAVE_CONFIG_H
# define HAVE_UNIX 1
#elif WIN32
# define HAVE_WIN32 1
#else
# error "No config.h provided for target and not a WIN32 system.\n Did you forget 'configure'?"
#endif

#if HAVE_WIN32
# include <io.h>
# define read _read
# define open _open

/* There is probably better place for this when using Win32-compilers, 
 * but this works OK */
#ifndef VERSION
# define VERSION "1.92a"
#endif

#endif

/* 
 * Default macro files
 */
#if HAVE_WIN32
# define USER_SGREPRC "sgreprc"
# define SYSTEM_SGREPRC "sgreprc"
#else
# define USER_SGREPRC	".sgreprc" 
# define SYSTEM_SGREPRC	DATADIR"/sgreprc"
#endif

/* 
 * Define this if you wan't sgrep to be able to exec external preprocessors 
 */
#define USE_EXEC

#ifndef DEFAULT_PREPROCESSOR
# define DEFAULT_PREPROCESSOR "m4 -s"
#endif

/* #define UNIX_PREPROCESS  */


/*
 * If you want stream mode by default define this
 */
/* #define STREAM_MODE */

/*
 * Default temp file directories
 */
#ifndef DEFAULT_TEMP_DIR
# if HAVE_WIN32
#  define DEFAULT_TEMP_DIR ""
# else
#  define DEFAULT_TEMP_DIR "/tmp"
# endif
#endif /* ifndef DEFAULT_TEMP_DIR */

/*
 * If this is defined we try to optimize away some sort operations 
 */
#define OPTIMIZE_SORTS

/* 
 * Sgrep has some very heavy assertion which slow sgrep down considerably.
 * However, since this is a development version of sgrep, i suggest that
 * you keep assertions on */
/* #define NDEBUG */

#ifdef ENABLE_ASSERTIONS
# ifdef NDEBUG
#  undef NDEBUG
# endif
# if !ENABLE_ASSERTIONS
#  define NDEBUG
# endif
#endif

#ifndef MEMORY_DEBUG
# define MEMORY_DEBUG 1
#endif

#ifdef SGREP_LIBRARY
# ifdef stderr
# undef stderr
# endif
# ifdef perror
# undef perror
# endif
# define stderr You_Should_Not_Use_Stderr
# define perror You_Should_Not_Use_Perror
# define exit You_Should_Not_Use_Exit
#endif
