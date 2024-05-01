---
title: "CVE-2021-4034 Exploit"
date: 2022-01-30
toc: true
tags: ["PwnKit", "exploit", "libc", "polkit", "LPE", "linux"]
---

[Root exploit](https://github.com/v-rzh/CVE-2021-4034) for the PwnKit vulnerability.
Check out the original report [here](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt).

*Use this exploit with an express permission of the target system owners.*

## Building

No dependencies needed besides libc. Just run `make`.

## Running

Running without options will execute the exploit:

```
[linux@linux ~]$ ./exploit
-----------------------------------------------------------------------------
 __\ / __   __  _ __           _ __        |    \ / _ ___
/   V |_ --- _)/ \ _)/| ---|_|/ \__)|_|    |     V |_) _/|_|
\__   |__   /__\_//__ |      |\_/__)  |    |       | \/__| |
-----------------------------------------------------------------------------
sh-5.1# whoami
root
sh-5.1#
```

You can customize the path to `pkexec` as well as the "from" charset:
```
[linux@linux ~]$ ./exploit -h
...
./exploit [-c] [-h] [-f from_charset] [-p /path/to/pkexec]
-----------------------------------------------------------------------------
    -c                  Just teardown - don't exploit
    -p <path>           Path to pkexec (default: "/usr/bin/pkexec")
    -f <from_charset>   Custom "from" charset (default: "UTF-8")
    -h                  Display this message
```

## What's the deal with `GIO_USE_VFS`?!

I saw a few people on social media ask why does the exploit fail if the
`GIO_USE_VFS=` is not defined? Why does it work with the older versions?

### The culprit

`daf3d5c2d15466a267221fcb099c59c870098e03` is the culprit. Here's the relevant
part of the diff:

```diff
--- a/src/programs/pkexec.c
+++ b/src/programs/pkexec.c
@@ -503,6 +503,9 @@ main (int argc, char *argv[])
   opt_user = NULL;
   local_agent_handle = NULL;

+  /* Disable remote file access from GIO. */
+  setenv ("GIO_USE_VFS", "local", 1);
+
   /* check for correct invocation */
   if (geteuid () != 0)
     {
```

Versions prior to this commit are exploitable without the need to define the
`GIO_USE_VFS` variable. The purpose of the commit is actually a red herring.
It's not what the variable means, it's *how it affects the environment*. For the
truth we must look to libc.

### Looking in libc

The process's environment in libc is represented by an array of `char *`s,
pointed to by this global variable:

```c
char **environ;
```

`environ` lives on the heap and is occasionally relocated. You might
already know where this is going. Check out this code snippet from
[setenv.c](https://code.woboq.org/userspace/glibc/stdlib/setenv.c.html):
```c
#if !_LIBC
# define __environ        environ
# ifndef HAVE_ENVIRON_DECL
extern char **environ;
# endif
#endif

int
__add_to_environ (const char *name, const char *value, const char *combined,
                  int replace)
{
  char **ep;

  // ... skipping

  ep = __environ;

  size = 0;
  if (ep != NULL)
    {
      for (; *ep != NULL; ++ep)
        if (!strncmp (*ep, name, namelen) && (*ep)[namelen] == '=')
          break;
        else
          ++size;
    }
  if (ep == NULL || __builtin_expect (*ep == NULL, 1))
    {
      char **new_environ;
      /* We allocated this space; we can extend it.  */
      new_environ = (char **) realloc (last_environ,
                                       (size + 2) * sizeof (char *));

  // ... skipping

      last_environ = __environ = new_environ;
    }
```

`__add_to_environ` is called by both `setenv(3)` and `putenv(3)` to accomplish
the same thing: set an environment variable. If the environment variable in
question is **not** defined, `environ` has to be reallocated to accommodate
a new entry (a pointer to the new environment `key=value` pair). If it is
defined, the size of the `environ` array has not changed and thus there is no
reason for reallocation. For brevity I've omitted that part of the code - I
encourage you to check it out.

### Tying it all together

Now let's come back to the exploit. If you've gotten this far, you probably
already know the methodology behind this exploit (if not please check out the
[original report](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)).
We are trying to sneak in an environment variable by passing an empty program
arguments (`argv`) to `pkexec`. When `argc` is truly empty (not even a program
name), the environment variables, which are adjacent to arguments clash with
it. We abuse this behavior to force `pkexec` to write a canonical path of a
target executable. However, before we get this part of code we get this:

```c
  setenv ("GIO_USE_VFS", "local", 1);
```

If this variable is not present in the environment `environ` will be
reallocated and it will never end up clashing with `argv` and the out of
bounds write will never take place.

