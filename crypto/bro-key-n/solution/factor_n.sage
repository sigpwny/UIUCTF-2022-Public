from tqdm import tqdm

N = 0x125165155e03af44b26423bed827a0651b9b7a7a7e79cac5b8d07a5ac0c25bf5b4f258c227348916a4befeb306be79d75a8e4fac2f7d8591d7f7f1e5006eaff2d32e93fcb1a50cb5bd449a84840c71f9f0bad999aeeed500dc32b7092d0b021adde2859d53c604f4b1613880fb4ada66c5a19da058bc7a6646b935c4d28a321bad0a39bb387465775dbc2ad7184ce221bd0ebc3de0fc0e9574b952a0cd7c2718d0696ba2b2ac5122708cd9643c8a28b3916d47b28f46c6aed7e91df1a78278039b9197223d1a8b0e88f2ddc55766a28eeaaa571e4daa7f2132d4028015a372b78b04b775987b1f6a420f5ad96d30d76cc3d354199c968a85390c85d4e12c7aeb050b1b04f430b23725ec5c13d0340138f66c6acfa459461b4ebfbe5af2b2d6907b8fa782e1652514529fdf343667e6875d7d1498f3d80cb76524580b6f2af01142f15bb10e91366dd882f7738fb2c242b417a4f2e0cfa5cd6fd6b63d1972901df69b9d5c4817782494309e80954d1c90e975592a47cce447619f5a3d5b7612bb667bbb14e1774964b14ea97cea375f99f7a19da543a9b4e9a978bdbfb2fff8f35e8e9597473888cb12b2efef708d871489e7ddb3ca64997ac6f4ad29c7e13d3545eb056a2e872ce32f13df5ecedd25b7bdd7c32464306466d2e5b7e48af9ace8a81e429581ab377468c7f03103ef758eaefb79a740489926fd8f26334fda1d65

e = 65537

dp_upper_bits = 0x0c55acb5a46475e4fcb3fc012a26f3b896bc34f7f047035c610d3739b98ce50a146ec49127e5e8667352e06dac2bfa37224a47c29cd904b9e418bf4f8484f60594906ccedac2257de1cdc54453ba892d1e1a00fe8fc7e1b415dfe4c5055bcab0af08a335a6d9a934fa98644d884794621738f8783eeb975a8468134811d36cd9544c9ac47086ba8865c81155bcdc39fe5c1376a07a59934ff25e18554517e462927c6f85571249c3ca82c7dd8691707186de2ea6cb69ced941c6f5f90cfb5d4

# Following notation of https://eprint.iacr.org/2020/1506.pdf Section 4.2.7

a = dp_upper_bits * 16^(512 - 383)

l = 20

# for kp in tqdm(range(e)):
for kp in range(28128, 28129): # Post-hoc knowledge, but looping would find this
    L = [[0 for i in range(l)] for j in range(l)]
    L[0][0] = N
    A = a + int(pow(e, -1, N))*(kp-1)
    X = 16^150
    for i in range(1, l):
        L[i][i-1] = A*X^(i-1)
        L[i][i] = X^i
    L = Matrix(L)
    L = L.LLL()

    R.<x> = PolynomialRing(Integers())
    for v in L:
        poly = sum([n / X^i * x^i for i,n in enumerate(v)])
        try:
            roots = poly.change_ring(ZZ).roots()
            if roots:
                r = roots[0][0]
                if 1 < gcd(A + r, N) < N:
                    p = gcd(A+r, N)
                    print("factored N!", p)
                    exit()
        except:
            continue

