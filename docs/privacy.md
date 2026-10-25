# Website privacy

I’m James Melvin, the maintainer of SourceOrrery. I use optional website
analytics to understand which guides and features people find useful and
to decide what to improve. There are no advertising integrations on this
site, and advertising consent is always denied when using Clarity.

## Your choice

Microsoft Clarity stays unloaded until you choose **Allow analytics**.
Choosing **No analytics** prevents its script and analytics requests,
including cookieless collection. The site works with either choice.

Use **Privacy choices** in any page’s footer to change your preference.
Switching analytics off saves your refusal, stops the loaded collector and
reloads the page. Subsequent pages leave Clarity unloaded. This stops
future collection; it does not withdraw data already sent while analytics
were allowed. Other open tabs respond to the preference change too.

Global Privacy Control and Do Not Track signals keep analytics off.
With JavaScript disabled, Clarity is never loaded.

## When analytics are allowed

Clarity collects website usage and interaction data, including page visits,
device/browser information, clicks, scrolling and session replays. This
helps me see which content is useful and where navigation needs work.
Clarity may set its analytics cookies, including `_clck` and `_clsk`, after
permission. Microsoft processes this data under its
[privacy statement](https://privacy.microsoft.com/privacystatement) and
[Clarity privacy information](https://learn.microsoft.com/clarity/faq).

Avoid putting confidential information in website URLs or search queries.
The documentation uses synthetic examples; the website does not connect
to your local vault, CLI or SDK. The Clarity tag is not part of those
applications and does not inspect your stored secrets.

## Browser storage

The site remembers theme and platform-tab preferences locally. It also
stores the analytics choice under `sourceorrery.analytics.v1`. Permission
is renewed after 180 days; a refusal remains until you change it or clear
site storage. When browser storage is unavailable, analytics start off on
each new page until you explicitly allow them there.

The hosting service may keep operational request logs independently of
Clarity. The banner controls the optional Clarity integration; it does not
control a browser extension, an external website you visit or your network
provider.

Questions or feedback: [contact me on LinkedIn](https://www.linkedin.com/in/jmelvin/)
or use the [GitHub repository](https://github.com/Netizine/sourceorrery).
