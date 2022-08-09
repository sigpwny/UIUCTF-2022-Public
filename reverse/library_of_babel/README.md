# Library of Babel

## Variations

- n = 100 (instead of current n = 2^256)
    - make it easier for direct LCG reversing step-by-step without finding
      closed form formula
- variable target page
    - currently, the target page is a fixed string
    - we can make it harder by making the target page reference parts of the
      input (for example, it could say "the coordinates to this page are ...")
