/*-
 * Copyright (c) 2001-2003 Allan Saddi <allan@saddi.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY ALLAN SADDI AND HIS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL ALLAN SADDI OR HIS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: sha.c 351 2003-02-23 23:24:40Z asaddi $
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "sha1.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

#include "version.h"

#ifndef lint
static const char rcsid[] =
	"$Id: sha.c 351 2003-02-23 23:24:40Z asaddi $";
#endif /* !lint */

static char *prog;

#define SHA_BUFFER_SIZE 65536
static uint8_t *buffer;

static int
shaFile (char *name, FILE *f, int which)
{
  union {
    SHA1Context sha1;
    SHA256Context sha256;
    SHA384Context sha384;
    SHA512Context sha512;
  } s;
  size_t len;
  uint8_t hash[SHA512_HASH_SIZE];
  int hashLen, i;
  int success = 1;

  switch (which) {
  case 1:
    SHA1Init (&s.sha1);
    break;
  case 2:
    SHA256Init (&s.sha256);
    break;
  case 3:
    SHA384Init (&s.sha384);
    break;
  case 5:
    SHA512Init (&s.sha512);
    break;
  default:
    abort ();
  }

  while ((len = fread (buffer, 1, SHA_BUFFER_SIZE, f)) > 0) {
    switch (which) {
    case 1:
      SHA1Update (&s.sha1, buffer, len);
      break;
    case 2:
      SHA256Update (&s.sha256, buffer, len);
      break;
    case 3:
      SHA384Update (&s.sha384, buffer, len);
      break;
    case 5:
      SHA512Update (&s.sha512, buffer, len);
      break;
    default:
      abort ();
    }
  }

  if (ferror (f)) {
#if HAVE_STRERROR
    fprintf (stderr, "%s: %s: %s\n", prog, name ? name : "stdin",
	     strerror (errno));
#else
    fprintf (stderr, "%s: %s: %s\n", prog, name ? name : "stdin",
	     "Read error");
#endif
    success = 0;
  }
  else {
    switch (which) {
    case 1:
      SHA1Final (&s.sha1, hash);
      hashLen = SHA1_HASH_SIZE;
      break;
    case 2:
      SHA256Final (&s.sha256, hash);
      hashLen = SHA256_HASH_SIZE;
      break;
    case 3:
      SHA384Final (&s.sha384, hash);
      hashLen = SHA384_HASH_SIZE;
      break;
    case 5:
      SHA512Final (&s.sha512, hash);
      hashLen = SHA512_HASH_SIZE;
      break;
    default:
      abort ();
    }

    for (i = 0; i < hashLen; i++)
      printf ("%02x", hash[i]);

    if (name)
      printf (" %s\n", name);
    else
      printf ("\n");
  }

  memset (&s, 0, sizeof (s));

  return success;
}

static void
help (int which)
{
  fprintf (stderr, "\nOptions:\n"
	   "\t-1\tUse SHA-1 %s\n"
	   "\t-2\tUse SHA-256 %s\n"
	   "\t-3\tUse SHA-384 %s\n"
	   "\t-5\tUse SHA-512 %s\n"
	   "\t-V\tDisplay version information\n"
	   "\t-h\tDisplay this summary\n\n"
	   "Only one of -1, -2, -3, -5 may be specified\n",
	   which == 1 ? "(Default)" : "",
	   which == 2 ? "(Default)" : "",
	   which == 3 ? "(Default)" : "",
	   which == 5 ? "(Default)" : "");
}

static void
usage (void)
{
  fprintf (stderr, "Usage: %s [-1235Vh] [file ...]\n", prog);
}

static void
burnBuffer (void)
{
  memset (buffer, 0, SHA_BUFFER_SIZE);
}

int
main (int argc, char *argv[])
{
  int ch;
  char *whichStr;
  int whichDef = 1;
  int which = 0;
  long offs;
  int i;
  FILE *f;
  int failure = 0;

  prog = argv[0];

  if ((whichStr = getenv ("SHA_DEFAULT")) && *whichStr) {
    switch (*whichStr) {
    case '1':
      whichDef = 1;
      break;
    case '2':
      whichDef = 2;
      break;
    case '3':
      whichDef = 3;
      break;
    case '5':
      whichDef = 5;
      break;
    }
  }

  while ((ch = getopt (argc, argv, "1235Vh")) != -1) {
    switch (ch) {
    case '1':
    case '2':
    case '3':
    case '5':
      if (!which)
	which = ch - '0';
      else {
	usage ();
	help (whichDef);
	exit (1);
      }
      break;
    case 'V':
      fprintf (stderr, "%s version " VERSION_STRING " (" VERSION_DATE ")\n",
	       prog);
      exit (1);
    case 'h':
      usage ();
      help (whichDef);
      exit (1);
    case '?':
    default:
      usage ();
      exit (1);
    }
  }
  argc -= optind;
  argv += optind;

  if (!which)
    which = whichDef;

  /* Allocate a suitable buffer. */
  if (!(buffer = malloc (SHA_BUFFER_SIZE + 7))) {
    perror (prog);
    exit (1);
  }

  /* Ensure it is on a 64-bit boundary. */
  if ((offs = (long) buffer & 7L))
    buffer += 8 - offs;

  atexit (burnBuffer);

  /* If given no arguments, process stdin. */
  if (!argc) {
    if (shaFile (NULL, stdin, which))
      exit (0);
    else
      exit (1);
  }

  for (i = 0; i < argc; i++) {
    if ((f = fopen (argv[i], "rb"))) {
      if (!shaFile (argv[i], f, which))
	failure = 1;
      fclose (f);
    }
    else {
#if HAVE_STRERROR
      fprintf (stderr, "%s: %s: %s\n", prog, argv[i], strerror (errno));
#else
      fprintf (stderr, "%s: %s: %s\n", prog, argv[i],
	       "No such file or directory");
#endif
      failure = 1;
    }
  }

  exit (failure);
}
