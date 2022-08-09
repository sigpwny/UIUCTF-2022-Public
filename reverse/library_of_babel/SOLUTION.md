# Library of Babel solution

Library of Babel is a reverse engineering and crypto challenge in UIUCTF 2022.
The premise of the program is a vast library one can search in using 4D
coordinates. These coordinates are combined into a large x value in
`Z_(39**3200)`, which is fed into an LCG with fixed parameters and ran a large
number of iterations. It uses the algorithm described [here][lcg-algo] to
quickly skip many iterations. To get the flag, you need to find the target page,
which begins with a specific string of characters.

To solve, first reverse engineer the coordinate format and how it is packed into
a single number for the LCG. Then, use the backwards iteration algorithm to skip
back to the original coordinates.

See `solve.py` for a solve script.

[lcg-algo]: https://www.nayuki.io/page/fast-skipping-in-a-linear-congruential-generator
