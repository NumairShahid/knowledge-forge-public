# Distribution status

**Public artifact available:** documentation only.

**Not available:** executable, wheel, container image, installer, source archive of the private engine, hosted Forge service.

The private Forge bootstrap is a repository-checkout installer, not a standalone package. The public edition must not advertise its bootstrap as working without access to private code.

Before any runtime release:

1. Choose a source-free distribution strategy and document limitations (Python bundling can remain reversible).
2. Audit generated artifacts for source leakage, credentials, and bundled third-party license obligations.
3. Decide and publish correct licensing/usage terms and notices.
4. Produce checksums and provenance for the *exact* release artifact.
5. Test the artifact in independent clean Codex and Claude environments without private repo access.
6. Publish only with an explicit human go/no-go decision.

A hosted service is an alternative when source secrecy is a firm requirement, but API deployment and trust boundaries require a separate review.
