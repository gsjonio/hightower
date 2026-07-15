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
  that it was not altered. hightower checks this and uses it to judge a process.
- **Risk verdict:** hightower's one-word take on each process -- `trusted`,
  `review`, or `suspicious`. It is a hint about where to look, **not** a
  diagnosis. `suspicious` does not mean "malware", and `trusted` is not a
  guarantee.

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
Scanned 252 processes: 0 suspicious, 3 to review.

RISK       PID  NAME          CATEGORY      PATH
review    4242  mystery.exe   unknown       C:\Users\me\Downloads\mystery.exe
trusted   1234  explorer.exe  core-windows  C:\Windows\explorer.exe
trusted   5678  chrome.exe    third-party-known  C:\Program Files\Google\Chrome\...
```

The most important rows float to the top. Reading left to right:

- **RISK** -- hightower's one-word take: `trusted`, `review`, or `suspicious`.
  A hint about where to look, not a diagnosis (see [Digital signature] above).
- **PID** -- the ticket number for that running program.
- **NAME** -- the process's name.
- **CATEGORY** -- what kind of thing it is: `core-windows` (part of Windows),
  `third-party-known` (recognized app), or `unknown` (hightower has no entry --
  common and not by itself a problem).
- **PATH** -- where it lives. `C:\Windows\...` and `C:\Program Files\...` are
  normal, trustworthy homes. `(restricted)` means Windows would not let hightower
  read this one's details -- **completely normal** for protected system programs;
  run as Administrator to see more. It does *not* mean the process is bad.

[Digital signature]: #a-few-words-explained

## Looking at one process in detail

To dig into a single process -- by name or by its PID number -- use `explain`:

```sh
hightower explain svchost.exe
hightower explain 1234
```

It prints a plain-language write-up: what the process is, whether many copies is
normal, its expected vs. actual location, and cautious advice on what to do if it
looks off. You can also get the whole scan as JSON for scripts with
`hightower scan --json`.

## "Why are there ten copies of the same thing?"

Totally normal. Windows runs many copies of some programs on purpose --
`svchost.exe` is the famous one; having a dozen at once is expected. A repeated
name is **not** a warning sign by itself.

The warning sign is a trusted name in the **wrong place**. A real `svchost.exe`
lives in `C:\Windows\System32`. A `svchost.exe` running from your `Downloads`
folder is the suspicious kind -- that is a trick malware uses, wearing a trusted
name like a costume. hightower flags exactly this: it marks such a process
`suspicious`.

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
