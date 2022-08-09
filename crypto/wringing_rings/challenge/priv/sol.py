import sympy as sp
import pwn
import random
from collections import defaultdict

def main():
    # pro = pwn.process(['python3', 'chal.py'])
    pro = pwn.remote('ssss.chal.uiuc.tf', 1337)
    pro.recvlineS()
    assert pro.recvlineS() == '[SSSS] Known shares of the secret polynomial: \n'

    minimum = 10

    print("Known shares of the secret polynomial: ")
    points = []
    for i in range(9):
        x, y = eval(pro.recvlineS()[6:])
        print(f"({x}, {y})")
        points.append((x, y))
    print()

    # Generate symbols
    sym_str = "S x"
    for i in range(1, minimum):
        sym_str += f" a{i}"
    S, x, *a = sp.symbols(sym_str)

    # Will 1 index the variables to line up with mathematical notation
    a.insert(0, None)

    p = S
    for i in range(1, minimum):
        p += a[i] * x**i
    print(f"{p = }")
    print()

    # generate the equations
    f = [p.subs(x, xi) - yi for (xi, yi) in points]
    for function in f:
        print("0 =", function)
    print()

    diffs = []
    for i in range(minimum - 1):
        for j in range(i + 1, minimum - 1):
            diffs.append(f[j] - f[i])

    # Solve for all vars in terms of last one
    sols = sp.solve(diffs, a[1:-1])
    for k, v in sols.items():
        print(f"{k} = {v}")
    print()

    # If minimum is even, then finding potential values for a_i is easy for even i
    # If minimum is odd, then finding potential values for a_i is easy for odd i
    # Honestly not sure why this is like this, but at least it's consistent
    # Ex:
    # minimum = 4
    # a1 = 14*a3 - 7467
    # a2 = 4441 - 7*a3 <--- EASY

    # minimum = 5
    # a1 = 77647 - 107*a4 <--- EASY
    # a2 = 59*a4 - 41793
    # a3 = 10057 - 13*a4 <--- EASY

    # generate possible vals for a_i for even i
    var = a[-1]
    idx = 2 - (minimum % 2)
    eq = sols[a[idx]]
    guess = 1
    while (val := eq.subs(var, guess)) >= 0:
        print(f"{guess = }, {val = }", end="\r")
        guess += 1

    # Since we update at the end of the loop, guess is 1 too high    
    upper = guess - 1
    print(
        f"Current Bounds on a{minimum - 1}: 1 <= a{minimum - 1} <= {upper}"
    )

    # Using the upper bound on var, we can also generate candidate values for var
    idx = 2 - ((minimum + 1) % 2)
    lower = float("inf")
    for guess in range(upper, 0, -1):
        val = sols[a[idx]].subs(var, guess)
        if val > 0:
            print(f"{guess = }, {val = }", end="\r")
            lower = min(lower, guess)
        else:
            break
    
    print()
    print(f"Overall Bounds: {lower} <= a{minimum - 1} <= {upper}")
    print()

    # Solve for S in terms of just var
    final_eqn = sp.solve(f[0], S)[0]
    for a_var in a[1:-1]:
        final_eqn = final_eqn.subs(a_var, sols[a_var])
    print(f"S = {final_eqn}")
    print()

    ans = final_eqn.subs(a[-1], lower)
    print(f"{ans = }")
    pro.sendline(str(ans))
    print(pro.recvline())
    print(pro.recvline())

if __name__ == "__main__":
    main()
