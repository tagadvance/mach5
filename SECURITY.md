# Security

mach5 decrypts your traffic. That is not a side effect, it is the mechanism —
everything it does needs the plaintext of the page. Before you run it, be sure
you want a thing on your network that can read every request every device makes.

## What mach5 is

An intercepting proxy. It terminates the TLS connection your browser thinks it
has with a website, using a certificate it mints on the spot for that hostname,
signed by a root certificate authority you generate and install on your own
devices. It then makes its own connection to the real site.

So there are two encrypted connections and mach5 sits in the middle of both,
holding the cleartext. This is the same technique used by corporate TLS
inspection appliances, and by every attacker you have ever been warned about.
The only thing separating the two is who is running it and why.

## The threat model

**mach5 assumes it is the most trusted thing on your network.** It is designed
for a machine you control, on a network you control, serving devices you own.
It is not hardened against a hostile local network, and it is not intended to be
exposed to the internet.

What mach5 defends against:

- A hostile *website*. Every page mach5 rewrites is untrusted input, and pages
  can reach the proxy's own endpoints because those endpoints live on every
  hostname. Cross-origin writes are refused, the settings a page can change are
  limited to ones that make the web look worse rather than make mach5 less safe,
  and the certificate bypass needs a single-use token issued by the warning page.
- A hostile *origin*. Response bodies are size-bounded before they are read and
  before they are decompressed, images are bounded by pixel count rather than by
  file size, and a body that cannot be decoded is passed through rather than
  guessed at.
- **Downgrade by accident.** Upstream certificate validation is on, and is
  disabled in exactly one file (`src/insecure.rs`), only for a host somebody
  typed a phrase for, only for a bounded time, only in memory, and every request
  that takes the permissive path is a warning in the log.

What mach5 does **not** defend against:

- **Anyone with the root private key.** It is total authority over every device
  that trusts it. Someone holding it can impersonate any website to any of those
  devices, on any network, indefinitely. It is the crown jewel and there is no
  second line of defence behind it.
- **An attacker on the machine running mach5.** Cleartext passes through memory
  by design.
- **A hostile local network.** There is no authentication on the proxy. Anything
  that can reach the listening port is served.

## If you run this

- **Do not expose it to the internet.** It binds 443 and answers for every
  hostname. On a public address it is an open proxy that will be found in hours.
- **Protect the root key.** `security/init.sh` writes it mode 600 and both files
  are gitignored. Do not copy it around, do not put it in a container image, do
  not commit it. If it leaks, treat every device that trusts it as compromised:
  generate a new root, install it everywhere, remove the old one.
- **Generate your own root.** Never install one somebody else generated,
  including one from a release artifact. If mach5 ever ships a prebuilt CA,
  that is a bug — report it.
- **Use `[passthrough] hosts` for anything that matters.** Banking, health,
  work. A listed host is never decrypted: mach5 reads the name out of the
  ClientHello without answering it and splices the two sockets, so it holds no
  key and sees no plaintext, and your client validates the real certificate
  itself. This is also the only way apps that pin their certificates will work.
- **Know what the log holds.** By default it records scheme, host and path — not
  the query string, where reset tokens and OAuth codes live. `[log] urls = "host"`
  drops the path too. Plugin output goes to the same log and mach5 cannot police
  what a plugin writes.
- **Remember it decrypts for everyone on that network,** not just you. If other
  people use it, they should know.

## With no `[ca]` configured

mach5 generates a throwaway root at startup and says so on the status page.
Nothing will trust it, and the next restart mints a different one. It exists so
the proxy runs out of the box for a look around; it is not a configuration to
deploy.

## Reporting a vulnerability

Open a **private** security advisory through GitHub's "Report a vulnerability"
button on this repository, rather than a public issue.

Please include what you did, what happened, and what you expected. A proof of
concept helps enormously. There is no bounty — this is one person's homelab
project — but findings are credited unless you would rather they were not.

Expect a first response within a week. If a fix is warranted it lands on `main`
with the advisory published alongside it.

## What is not a vulnerability

- That mach5 can read your traffic. That is the entire premise.
- That a certificate-pinning app refuses to connect. That is the app working
  correctly; use `[passthrough] hosts`.
- Anything requiring the root private key, or access to the machine running the
  proxy. Both are already inside the trust boundary.
- Exposure caused by running it on a public address, which the documentation
  tells you not to do.

## No warranty

mach5 is provided under the terms in `LICENSE`, which includes a disclaimer of
warranty and a limitation of liability. It is a homelab project written for its
author's own network. It has not been independently audited or penetration
tested. Judge it accordingly before putting it between yourself and the web.
