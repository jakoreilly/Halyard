# Reaching it from outside

Halyard binds `127.0.0.1`. Getting to it from your phone is a tunnelling problem, and it is
a solved one — you do not need to open a port, forward anything on your router, or put a
bearer token on the public internet.

## Why not just bind `0.0.0.0`?

You can. `halyard start --host 0.0.0.0` works and prints a warning saying what it exposes.

What you give up:

- **Everything on the network can reach your agent**, with a bearer token as the only gate.
- **No HTTPS**, so the token travels in the clear and, more practically, the browser's
  `PushManager` does not exist over plain HTTP. You silently lose push and drop to in-page
  alerts that only fire while the page is open — which defeats most of the point.
- **It only works on that network.** A tunnel works from anywhere.

The tunnels below are all less work than a firewall rule.

---

## Tailscale Serve — recommended

A private network between your own devices, with real HTTPS certificates on a name only your
devices resolve. Nothing is published.

```sh
# once, on the machine running Halyard and on your phone
tailscale up

# then
tailscale serve --bg 4545
tailscale serve status        # prints your https:// hostname
```

Put that hostname in your config so notification taps land in the right place:

```json
{ "publicUrl": "https://desk.tail1234.ts.net" }
```

Then `halyard token --url` gives you the link to open on the phone.

**Why this one:** device identity is handled by the network, so the bearer token is a second
factor rather than the only one. There is no listening port on any public interface, and
nothing to leave accidentally exposed when you stop paying attention.

<details>
<summary>Tailscale Funnel — read this before you use it</summary>

`tailscale funnel` publishes to the **entire internet**. Your Halyard token becomes the only
thing between an anonymous stranger and a shell on your machine.

Do not do this. If you genuinely need it — you are handing access to someone with no
Tailscale account — put an authenticating proxy in front and treat the bridge as
compromised the moment the token leaks.
</details>

---

## Cloudflare Tunnel

No account needed for a quick throwaway URL:

```sh
cloudflared tunnel --url http://127.0.0.1:4545
```

It prints a random `https://<words>.trycloudflare.com`. That URL is **public** — anyone who
guesses or is given it reaches your bridge, gated only by the token. Fine for ten minutes of
testing; for anything standing, use a named tunnel with Cloudflare Access in front:

```sh
cloudflared tunnel create halyard
cloudflared tunnel route dns halyard halyard.example.com
cloudflared tunnel run --url http://127.0.0.1:4545 halyard
```

---

## SSH port forward

Nothing to install, if you already have SSH to the machine:

```sh
ssh -N -L 4545:127.0.0.1:4545 you@machine
```

Then use `http://127.0.0.1:4545` on the forwarding device. Because it is *localhost* to the
browser, it counts as a secure context and **push works** — the one case where plain HTTP
does not cost you anything.

Awkward on a phone (you need an SSH client holding the tunnel open), but excellent from a
laptop.

---

## Ngrok and friends

Same shape as a quick Cloudflare tunnel: a public HTTPS URL, token-gated only.

```sh
ngrok http 4545
```

Convenient, and the same caveat applies — that URL is on the public internet for as long as
it is up.

---

## Checklist for any tunnel

- [ ] `host` is still `127.0.0.1`. The tunnel connects to loopback; nothing needs to bind wider.
- [ ] `publicUrl` is set to the tunnel's origin, so a notification tap with no tab open lands
      on the right host instead of the 401 page.
- [ ] The URL is **HTTPS**, or push will not work. The page's push hint tells you which tier
      is actually in force — believe it over the URL bar.
- [ ] You know who else can reach the URL. Private tailnet, or the whole internet? They are
      very different answers.
- [ ] You have read the workspace and permission-mode sections of
      [SECURITY.md](../SECURITY.md), because the tunnel only decides *who* can reach the
      bridge, not *what* the bridge can do once reached.

## Adding it to the home screen

Open the tokened URL on the phone and use "Add to Home Screen". Halyard serves a manifest
with the token baked into `start_url`, so the icon launches straight in — a PWA launched from
the home screen carries no query string of its own, which is exactly why the manifest is
generated per-install rather than served as a static file.

If the icon lands on the 401 page, `publicUrl` is probably unset or wrong.
