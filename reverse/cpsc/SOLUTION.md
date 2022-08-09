# CPSC writeup

See solve.py

One way to do it:
- notice that the length stays constant after mexing
- identify that [CPC][github] was used to compile the challenge
    - there are some assert macros still left in the compiled binary that reveal
      this
- compile your own binary, see how cpc turns loops into recursive functions
- reverse each step of the algorithm (split, merge, xorshift)

[github]: https://github.com/kerneis/cpc
