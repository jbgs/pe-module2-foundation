# ADR 0008: the golden path

Status: accepted. Date: 2026-11-17.

## Context

A platform is adopted or it is not, and adoption lives or dies at the front door. If a Builder can say what they need and
get a running, compliant environment in minutes, they will use the platform; if they have to file a ticket, wait, or
assemble it themselves, they will go around it, and everything behind the door sits unused. Everything in Modules 2 and 3
(the delivery pipeline, the sandbox, the policy, the audit record) is behind that door.

What a Builder had to do before this: know that a workflow called `Deploy` exists and what its inputs mean, have the GitHub
command line authenticated with the right scope, run it with the right parameters, and wait. For an agent's workspace there
was nothing at all: a Builder assembled a sandbox, its data and its policy by hand, and nothing said they had got it right.

## Decision

### An intent in words, and a few paved roads

A Builder describes what they need in their own words (`golden_path.py new "I need a sandbox for an agent to analyse churn
data"`), on the command line or in the form of the workflow `Golden path`. The request is matched to a **paved road**. There
are two, because those are the two things a Builder here actually needs:

| Road | What it makes | How |
|---|---|---|
| `agent-sandbox` | A clean copy of the agent workspace: invented data only, the plan, the policy, and the command to run an agent in it. Ready for an agent. | Locally, in a fraction of a second |
| `service-dev` | The development environment of Module 2 | By starting the `Deploy` workflow that already exists, with zero tasks unless asked |

Not more: a road for everything a Builder might one day need is a road nobody maintains. Start narrow, and let the misses
(below) say what the next road is.

### The compliant choices are the defaults

Each road carries its compliant choices as data (`road.json`): for the sandbox, no network, a read-only root filesystem, no
capabilities, synthetic data only, the policy and the audit record; for the service, the one allowed address, the
read-only root, the immutable tagged image, the automatic rollback, the locked remote state, and size zero until asked. The
Builder gets them **by default rather than by expertise**. A road that lacks them, or gives one up, is refused: by the
command, which will not make an environment from it, and by a test, so a road cannot be added that quietly drops one. (The
check refused my own first draft of `service-dev` for writing a default as "synthetic only: the service holds no data of
its own" instead of exactly "synthetic only", which is the strictness meant.)

### The match is deterministic, and what it cannot match is recorded

The match is by weighted keywords, with no model: it is predictable, it can be tested, and it can be audited. A request
needs a minimum score, and one that two roads match equally well is not guessed: it is refused and the Builder is asked which
they mean. A request that no road covers is refused, **and recorded**. That record is the most honest sign of adoption there
is, because it says what the path is missing before a Builder goes and builds it by hand.

The limit: it matches words, not meaning. A Builder who phrases the same need in words that no keyword holds will be told the
path does not cover it. That is a miss, and it is recorded, and a road's keywords are the first thing to extend.

### What is paid for asks first

`service-dev` starts paid infrastructure, so by default it only says what it would do, what it costs and how to tear it down,
and runs on `--yes`. A task is left running only with `--running`. Nothing is created by a request that was not asked
for plainly.

### Adoption is measured from the first use

Every request leaves a record in a usage log whose records are chained by hashes, like the audit record: an environment made,
an environment understood and waiting for a yes, an intent the path did not cover, a road refused, a workflow that could not be
started, each with who asked, where from, and how long it took. `golden_path.py report` turns it into the figures that
matter: environments made by road, the share of requests the path covered, the requests it could not and what they said,
the time to an environment, and the signal that tells whether Builders **choose** the path or **go around** it.

That last signal is the runs of the agent that do not come from an environment of the path. The enforcement point accepts
`--environment` and writes it in the first record of every run; a run without one is a run that went around. The runs that test
the platform itself are not counted either way. The logs of the Golden path workflow are written to the audit store, so that
adoption is counted in one place and cannot be edited afterwards.

### What a Builder types is never a command

The form of the workflow `Golden path` takes free text. That text reaches the script as an environment variable, and is
never pasted into a command line, which is how a request becomes a command. A test fails if anyone changes that.

## What this measured

| | Before | With the path |
|---|---|---|
| To get a development environment | Know the workflow, its inputs, an authenticated command line, run it; 1 min 41 s to 4 min 48 s for the pipeline itself | One sentence; the pipeline is the same, so its time is |
| To get a sandbox for an agent | Assemble the data, the plan and the policy by hand, with nothing to say it was right | One sentence; the whole process takes about 54 ms (the path measures its own work at about 2 ms, a different figure) |

The second row is trivial in time because it makes a folder, and should not be read as more: what it replaces is the
assembling and the guessing, and what it adds is that the result is compliant by default, and is the same every time.

## What this does not do, stated

- **There is one Builder.** The measurement of adoption is built and works, and it has nothing to say yet: with one user,
  no figure about whether Builders choose the path means anything. What was shown is that the instrument counts what it
  should (7 requests, 4 covered, 3 not, 3 environments made, the time of each), not that Builders adopt.
- **`service-dev` is not self-service to tear down.** It is made by a request, and destroyed by an administrator with
  `terraform destroy`: the pipeline's role cannot destroy it, on purpose (see ADR 0006 on what that role may do). A road that
  can be made but not unmade by the Builder is half a road.
- **Going around the path is seen only where it leaves a record.** A run of the agent without an environment is seen
  because it leaves an audit log. A Builder who never uses the platform at all leaves nothing, and is invisible to this
  measure.
- **There is no portal.** The market's lesson is to build the platform, with its roads and its defaults, before the portal; the
  front door here is a command and a form. A portal would be a shop front over the same roads.
- **A request typed locally is counted locally.** Only requests through the workflow reach the audit store; the local
  usage log is real and verifiable, but it is on that machine.

## Consequences

- A Builder gets an environment by describing it. What it comes with is not their expertise to supply.
- Adding a road is adding a folder with a `road.json`; the checks and the report need no change.
- What the path cannot give is written down, with who asked, so the next road is chosen by evidence.
