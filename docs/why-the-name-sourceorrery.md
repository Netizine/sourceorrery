# Why the name SourceOrrery?

As a kid, two things fascinated me: **orreries and *The Lord of the Rings*.**
A slightly unusual combination, perhaps, but stay with me.

## A little mechanical universe

An orrery is an extraordinary piece of engineering. It takes the movements
of planets and moons and translates them into something you can watch,
follow and understand. Layers of gears, different orbital speeds, multiple
motions, all coordinated through one intricate mechanism. The mathematics
behind something unimaginably vast becomes a little mechanical universe in
front of you. To me, that has always been magical.

But something else about orreries caught my imagination: **even these
remarkable machines had to adapt to discovery.** Early grand orreries
represented the six known planets, reaching out to Saturn. The Science
Museum's [grand orrery enlarged in 1733](https://collection.sciencemuseumgroup.org.uk/objects/co1522/george-iis-grand-orrery)
is one such example. Uranus was discovered in 1781 and Neptune in 1846,
expanding the solar system those mechanisms were trying to explain. Then
came Pluto in 1930, followed, eventually, by its reclassification as a
dwarf planet. [NASA's history of the planets](https://science.nasa.gov/solar-system/planets/what-is-a-planet/)
follows that changing picture. Apparently, even our model of the solar
system has changing requirements.

I love that. However beautiful the mechanism, however clever the
engineering, there is always another discovery waiting to challenge the
design. You have to leave room for what you do not yet know.

## A little source-code sorcery

Then there was Tolkien.

Born in South Africa, with England becoming home,
[J. R. R. Tolkien](https://www.tolkienestate.com/life/biography/) had a
connection to both places that feels rather familiar to me. And, of course,
he gave us the world of *The Lord of the Rings*. Within that world was a
certain wizard called Gandalf.

I found my first grey hair in my twenties. Let's just say my transformation
into **Gandalf the Grey** has been a fairly committed, long-term project.
Somewhere along the way, I also picked up a few magic tricks with source
code. A little *sorcery*, if you will. Usually accompanied by coffee and the
occasional spell that refuses to compile.

Now, in a world of agentic AI, I get to play orchestrator in an even more
extraordinary playground. I can apply ideas, experience and guidance, shape
how the pieces fit together, and watch something that began as a thought
become working software. There is still plenty to question, test and refine.
For me, that is part of the fun.

## How that became SourceOrrery

That fascination with coordinated moving parts carries through into
SourceOrrery: encrypted vaults, provider integrations and language SDKs
working through a shared Rust core. Each part has a clear responsibility,
while the core keeps the rules for retrieving and managing secrets
consistent. There is plenty happening underneath, all serving a
straightforward purpose: keeping credential values out of project files
and making them available to applications at runtime.

**Secrets belong to the runtime, not the repository.**

The aim is to make that distinction practical. A developer or coding agent
can work with a project's declared requirements without needing the actual
passwords to edit its configuration. An application can resolve those
references when it runs. Metadata, versioning, time windows and audit
records make the moving parts easier to follow than a collection of copied
`.env` files.

The orrery also reminds me to leave room for discovery. A project might
start with local storage and later use AWS Secrets Manager, Azure Key Vault
or HashiCorp Vault for particular values. The references in its manifest
can stay the same. The [architecture](architecture.md) gives those providers
their own place in the mechanism, and the [roadmap](roadmap.md) makes room
for controls that still need to be built. Testing, documented boundaries
and a willingness to revise the design are part of the engineering too.

So the name brings together a few things that have stayed with me: the
source code I have spent decades working with, the intricate engineering
of an orrery, the need to keep adapting, and a little of the sorcery that
made a young boy believe a grey-haired wizard could do extraordinary things.

**SourceOrrery.**

Plus, every other name was taken.

For the practical reasons behind the project, read [Why SourceOrrery?](why-sourceorrery.md).
