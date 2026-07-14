# hightower -- Beginner's Guide

EN | [PT-BR](GUIDE.pt-BR.md)

This guide is for people who are **not** technical. No prior knowledge needed.
If a word looks scary, we explain it here in plain language.

## What is hightower for?

Your computer is always running many small programs in the background, even when
you are not doing anything. Some are part of Windows. Some belong to apps you
installed. And once in a while, one of them is something that should not be
there.

**hightower** shows you that list and explains, in plain words, what each item
is -- so you can notice the odd one out.

> hightower is a helper, **not an antivirus**. It points at things worth a look;
> it does not remove anything and it is not always right. Think of it as a
> friend who knows Windows well pointing and saying "hm, that one looks off."

## A few words explained

- **Process:** one running program. Not the icon you clicked -- the *engine*
  behind it. One app can have several processes.
- **PID:** a number Windows gives each process, like a ticket number. It is
  different every time the process starts. You rarely need it.
- **Path:** *where* the program lives on your disk, e.g.
  `C:\Windows\System32\svchost.exe`. This is a big clue: trustworthy Windows
  programs live in trustworthy folders.
- **Digital signature:** a kind of tamper-proof seal from the company that made
  the program (like Microsoft). If the seal is valid, you know who made it and
  that it was not altered. hightower will use this in a future version.

## Running it

hightower is a **command-line** tool -- you type a command instead of clicking.
Open a terminal (press Start, type "Terminal" or "PowerShell", hit Enter), then:

```sh
hightower scan --all
```

You will get a table of every running process. To see more detail about
protected system programs, run the terminal **as Administrator** (right-click it
-> "Run as administrator").

## Reading the table

```text
Scanned 252 running processes:

  PID  NAME                 PATH
    4  System               (restricted)
 1234  explorer.exe         C:\Windows\explorer.exe
 5678  chrome.exe           C:\Program Files\Google\Chrome\Application\chrome.exe
```

- **NAME** -- the process's name.
- **PATH** -- where it lives. `C:\Windows\...` and `C:\Program Files\...` are
  normal, trustworthy homes.
- **(restricted)** -- Windows would not let hightower read this one's details.
  This is **completely normal** for protected system programs. Run as
  Administrator to see more. It does *not* mean the process is bad.

## "Why are there ten copies of the same thing?"

Totally normal. Windows runs many copies of some programs on purpose --
`svchost.exe` is the famous one; having a dozen at once is expected. A repeated
name is **not** a warning sign by itself.

The warning sign is a trusted name in the **wrong place**. A real `svchost.exe`
lives in `C:\Windows\System32`. A `svchost.exe` running from your `Downloads`
folder is the suspicious kind -- that is a trick malware uses, wearing a trusted
name like a costume. (hightower will flag exactly this in a future version.)

## If something looks off -- what to do, and what NOT to do

**Do NOT** immediately delete or "kill" a process because it looks unfamiliar.
Many strange-looking names are a normal part of Windows, and stopping the wrong
one can break your system or make it restart.

Instead:

1. **Look at the PATH.** Is it in `C:\Windows\...` or `C:\Program Files\...`?
   Those are normal. Is it in `Downloads`, `Temp`, or `AppData`? That is worth
   more attention.
2. **Search the exact name online**, together with the word "process" -- e.g.
   "what is `ctfmon.exe` process". Reputable results will tell you if it is
   normal.
3. **When unsure, ask someone you trust** who knows computers. There is no rush.
4. If you have good reason to think it is malware, run a real antivirus scan.
   hightower is not one.

## What hightower will never do

- It will never change, stop, or delete anything on your computer. It only
  *looks*.
- It will never use the internet or send your information anywhere. Everything
  happens on your machine.
- It will never tell you, with certainty, that something is malware. It gives you
  clues; you stay in charge.

## Still curious?

The [project wiki](https://github.com/gsjonio/hightower/wiki) goes deeper (it is
more technical). For questions, see the
[FAQ](https://github.com/gsjonio/hightower/wiki/FAQ).
