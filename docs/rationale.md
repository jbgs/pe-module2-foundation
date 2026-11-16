# Rationale: tooling choices and a foundation for the agentic layer

I chose each tool for the property it gives, not for its brand, and kept the contract between layers narrow, so any of them can be replaced without rebuilding the rest.

- **Everything as code.** Infrastructure is declared, and a change shows a reviewable plan before anything is applied. Any declarative tool with a plan step and remote state gives the same property. The `main` branch accepts changes only through a pull request.
- **Disposable environments.** A container image plus declarative infrastructure is all an environment needs. I destroyed and recreated the development environment: 19 resources came back identical and the next plan reported no changes. The recreate took 4 min 48 s, then 1 min 41 s.
- **Pipeline.** Workflows are code. They use short-lived federated credentials instead of stored keys, and third-party steps are pinned by hash. Each release builds, scans, applies and then verifies that the requested version is the one running. Rollback was exercised twice: by hand (4 min 20 s) and automatically, when a deliberately broken release made the platform's deployment circuit breaker restore the previous version. Any CI system with identity federation could host the same stages.
- **AI in the pipeline.** The review is advisory: it runs in a separate workflow with no cloud credentials, cannot approve or merge, and treats the diff as untrusted data. The model is a setting, and the provider is isolated in one function. It leaves a structured trace with hashes, not content. In a test of five planted defects it flagged all five (median 12.8 s); it did not speed up the pipeline, it gave earlier feedback.

**Ready for the agentic layer.** An agent's change arrives as a pull request and meets the same rules as a person's, with no privileged shortcut. Agents can be given narrow roles bounded by a permissions limit. The seams are already in place: a versioned trace schema, JSON request logs, a scan gate that is switched off but wired in, and a verify step that any later gate can follow.

**Not done yet.** Required status checks are not enforced on `main`, the scan gate is off, there is one environment, and there are no sandboxes. Those are Module 3 work, and none needs a rebuild.
