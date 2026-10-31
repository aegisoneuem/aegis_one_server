-- 0015_os_fixed_builds.sql
-- The OS build each Windows KB brings a product to, from MSRC's
-- Remediations[].FixedBuild ("10.0.26100.9711"). It drives the PatchBaseline
-- the server pushes to agents: "for your build, the latest KB is ...". The
-- agent applies a baseline only when its build string matches exactly, and
-- uses it for an offline hint; the scan report stays the source of truth.
--
-- os_kind separates client and server releases that share a build number but
-- not a KB (Windows 11 24H2 and Windows Server 2025 are both 26100).
CREATE TABLE os_fixed_builds (
    patch_id        UUID NOT NULL REFERENCES patch_catalog(id) ON DELETE CASCADE,
    kb              TEXT NOT NULL,          -- 'KB5127648'
    product_name    TEXT NOT NULL,          -- MSRC product, e.g. 'Windows 11 Version 24H2 for x64-based Systems'
    os_kind         TEXT NOT NULL CHECK (os_kind IN ('client', 'server')),
    architecture    TEXT NOT NULL CHECK (architecture IN ('x86', 'x64', 'arm64')),
    os_build        INTEGER NOT NULL,       -- 26100
    ubr             INTEGER NOT NULL,       -- 9711
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kb, product_name)
);
CREATE INDEX idx_ofb_family ON os_fixed_builds (os_kind, architecture, os_build, ubr DESC);
