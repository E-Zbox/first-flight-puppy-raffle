## My NOTES

For the Cyfrin Updraft Smart Contract Auditing Course | PuppyRaffle SC

## Table of Contents

- [STEP ONE: SCOPING PHASE](#table-of-contents)

### STEP ONE: SCOPING PHASE

**INSTALLATION / SETUP**

- Go through the README.md file
- Install necessary dependencies
- Go to specific repository branch or commit Hash

**RUN SOME TOOLS**

- Slither

```bash
slither .
```

- Aderyn

```bash
aderyn --root .
```

- **Two finger click** on `src` folder and click on **Solidity Metrics**

**TIME TO READ DOCUMENTATION**

You can make notes (in a `.notes.md` file) of what you think the project is about in your own words. Don't spend much time on it. Get an idea of the project and head over to the codebase 🚀

**CODEBASE**

On the Codebase, refer to the **Solidity Metrics** Output to get the main entry point.

- Scroll to the bottom and expand the **Contract Summary** tab.

**DOCUMENT FINDINGS IN `findings.md` file (or alias)**

Going back to the **Solidity Metrics** Output, the next function is the `PuppyRaffle:refund` function.
