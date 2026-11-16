# Release testing policy

## Clean-machine rule

Do not treat a maintainer's development Mac as proof that a release is portable.
It may have developer tools, package managers, Python, codecs, or libraries
that quietly make a broken bundle appear to work.

Before publishing a release, test the ZIP or DMG on a clean macOS user account,
virtual machine, or another Mac that has never had Homebrew installed. The
tester must not install Python, pip packages, command-line tools, or libraries
to make the app open.

## Required checks

1. Download the same ZIP or DMG intended for the public.
2. Install normally and launch from Finder.
3. Exercise one meaningful app workflow and any bundled helper tool.
4. Inspect bundled Mach-O binaries with `otool -L`; fail the release if a
   non-system dependency resolves outside the app bundle.
5. Run the app's available self-test or smoke test.

Record the macOS version, Mac architecture, artifact name, and result in the
release notes. A result that works only on the maintainer's machine is not a
passing release test.
