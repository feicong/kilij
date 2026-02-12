"""
Test Kilij opaque predicates against Z3.

Tests whether Z3 can prove the Grassmann-Plucker and q-binomial
predicates are always true (i.e., find a counterexample where they != 0).
If Z3 times out, the predicate resists symbolic analysis.
"""

import time
from z3 import *

def test_grassmann_plucker(bits, timeout_ms=60000):
    """
    Grassmann-Plucker relation on 2x2 minors of a 2x4 matrix.
    d12*d34 - d13*d24 + d14*d23 == 0

    This holds for ALL values over any commutative ring,
    including bitvectors with wraparound.
    """
    print(f"\n{'='*60}")
    print(f"Grassmann-Plucker relation ({bits}-bit bitvectors)")
    print(f"Timeout: {timeout_ms/1000:.0f}s")
    print(f"{'='*60}")

    # 8 free bitvector variables (the 2x4 matrix entries)
    a, b, c, d = BitVecs('a b c d', bits)
    e, f, g, h = BitVecs('e f g h', bits)

    # 6 minors of the 2x4 matrix [[a,b,c,d],[e,f,g,h]]
    d12 = a * f - b * e
    d13 = a * g - c * e
    d14 = a * h - d * e
    d23 = b * g - c * f
    d24 = b * h - d * f
    d34 = c * h - d * g

    # Grassmann-Plucker relation
    relation = d12 * d34 - d13 * d24 + d14 * d23

    # Ask Z3: can you find values where relation != 0?
    s = Solver()
    s.set("timeout", timeout_ms)
    s.add(relation != 0)

    start = time.time()
    result = s.check()
    elapsed = time.time() - start

    if result == unsat:
        print(f"Result: UNSAT (Z3 PROVED it's always 0)")
        print(f"Time: {elapsed:.3f}s")
        print(f"=> Z3 CAN solve this at {bits}-bit. Predicate is NOT resistant.")
    elif result == unknown:
        print(f"Result: UNKNOWN (Z3 timed out or gave up)")
        print(f"Time: {elapsed:.3f}s")
        reason = s.reason_unknown()
        print(f"Reason: {reason}")
        print(f"=> Z3 CANNOT solve this at {bits}-bit within {timeout_ms/1000:.0f}s.")
    elif result == sat:
        print(f"Result: SAT (found counterexample - THIS SHOULDN'T HAPPEN)")
        print(f"Time: {elapsed:.3f}s")
        m = s.model()
        print(f"Counterexample: a={m[a]}, b={m[b]}, c={m[c]}, d={m[d]}")
        print(f"                e={m[e]}, f={m[f]}, g={m[g]}, h={m[h]}")

    return result, elapsed


def test_qbinomial(bits, n=6, timeout_ms=60000):
    """
    q-binomial theorem identity.
    Product form: Π_{r=0..n-1} (1 + t * q^r)
    Sum form: Σ_{k=0..n} C(n,k;q) * t^k * q^(k*(k-1)/2)

    The difference should always be 0.
    """
    print(f"\n{'='*60}")
    print(f"q-Binomial theorem identity ({bits}-bit bitvectors, n={n})")
    print(f"Timeout: {timeout_ms/1000:.0f}s")
    print(f"{'='*60}")

    t, q = BitVecs('t q', bits)
    one = BitVecVal(1, bits)
    zero = BitVecVal(0, bits)

    # Product form: Π_{r=0..n-1} (1 + t * q^r)
    product = one
    q_power = one  # q^0 = 1
    for r in range(n):
        product = product * (one + t * q_power)
        q_power = q_power * q

    # Gaussian binomial coefficients via recurrence
    # C(n, k; q) = C(n-1, k; q) + q^(n-1-k) * C(n-1, k-1; q) ... wait
    # Actually: C(n, k; q) satisfies C(n,k;q) = C(n-1,k;q) + q^(n-k) * C(n-1,k-1;q)
    # with C(n,0;q) = 1 and C(0,k;q) = 0 for k>0

    # Build table
    C = [[zero for _ in range(n + 2)] for _ in range(n + 2)]
    for i in range(n + 1):
        C[i][0] = one

    q_powers = [one]
    qp = one
    for i in range(1, n + 1):
        qp = qp * q
        q_powers.append(qp)

    for i in range(1, n + 1):
        for k in range(1, i + 1):
            # C(i, k; q) = C(i-1, k; q) + q^(i-k) * C(i-1, k-1; q)
            C[i][k] = C[i - 1][k] + q_powers[i - k] * C[i - 1][k - 1]

    # Sum form: Σ_{k=0..n} C(n,k;q) * t^k * q^(k*(k-1)/2)
    sumval = zero
    t_power = one
    for k in range(n + 1):
        exp = k * (k - 1) // 2
        # compute q^(k*(k-1)/2)
        q_half = one
        for _ in range(exp):
            q_half = q_half * q
        sumval = sumval + C[n][k] * t_power * q_half
        t_power = t_power * t

    # The identity: product - sum == 0
    diff = product - sumval

    s = Solver()
    s.set("timeout", timeout_ms)
    s.add(diff != 0)

    start = time.time()
    result = s.check()
    elapsed = time.time() - start

    if result == unsat:
        print(f"Result: UNSAT (Z3 PROVED it's always 0)")
        print(f"Time: {elapsed:.3f}s")
        print(f"=> Z3 CAN solve this at {bits}-bit. Predicate is NOT resistant.")
    elif result == unknown:
        print(f"Result: UNKNOWN (Z3 timed out or gave up)")
        print(f"Time: {elapsed:.3f}s")
        reason = s.reason_unknown()
        print(f"Reason: {reason}")
        print(f"=> Z3 CANNOT solve this at {bits}-bit within {timeout_ms/1000:.0f}s.")
    elif result == sat:
        print(f"Result: SAT (found counterexample - THIS SHOULDN'T HAPPEN)")
        print(f"Time: {elapsed:.3f}s")
        m = s.model()
        print(f"Counterexample: t={m[t]}, q={m[q]}")

    return result, elapsed


if __name__ == "__main__":
    print("Kilij Opaque Predicate Z3 Resistance Test")
    print("==========================================")
    print()
    print("Testing whether Z3 can prove these identities are always true.")
    print("If Z3 times out, the predicate resists static symbolic analysis.")
    print()

    # Test Grassmann-Plucker at increasing bitvector widths
    for bits in [8, 16, 32, 64]:
        timeout = 60000 if bits <= 32 else 300000  # 5 min for 64-bit
        test_grassmann_plucker(bits, timeout_ms=timeout)

    print("\n" + "=" * 60)
    print("Now testing q-binomial theorem...")
    print("=" * 60)

    # Test q-binomial at increasing widths
    for bits in [8, 16, 32, 64]:
        timeout = 60000 if bits <= 32 else 300000
        test_qbinomial(bits, n=6, timeout_ms=timeout)

    print("\n\nDone.")
