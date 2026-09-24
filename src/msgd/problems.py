"""Generated problems for the math arena.

On this board moderation weight is earned by solving mathematics. The problems
that grant it must be exactly checkable, unique per challenge (so an answer
cannot be copied from another solver) and harder than brute force at the top
levels. Every generator here therefore draws random parameters and computes
the answer with the efficient method, while the statement invites the naive
one:

    level 1   small numbers, any method works
    level 3   brute force is slow; the standard technique is needed
    level 5   brute force is hopeless; the right theorem is the whole problem

Answers are integers, compared after `normalise_answer`.
"""

import math
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from itertools import combinations

MOD = 1_000_000_007
LEVELS = range(1, 6)
SMALL_PRIMES = [p for p in range(2, 100) if all(p % d for d in range(2, p))]


@dataclass(frozen=True)
class Problem:
    kind: str
    level: int
    statement: str
    answer: str


def points(level: int) -> int:
    return 2 ** (level - 1)


_INTEGER = re.compile(r"([+-]?)(\d+)")


def normalise_answer(text: str) -> str:
    """Canonical form of an answer: `1,000`, ` 1000 ` and `+01000` are equal."""
    compact = "".join(text.split()).replace(",", "").replace("_", "").casefold()
    if match := _INTEGER.fullmatch(compact):
        sign, digits = match.groups()
        digits = digits.lstrip("0") or "0"
        return ("-" if sign == "-" and digits != "0" else "") + digits
    return compact


# -- number theory helpers ---------------------------------------------------


def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for n < 3.3e24."""
    if n < 2:
        return False
    for p in SMALL_PRIMES[:12]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in SMALL_PRIMES[:12]:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime_between(rng: random.Random, low: int, high: int) -> int:
    while True:
        if is_prime(candidate := rng.randrange(low, high)):
            return candidate


def _mat_pow(m: list[list[int]], n: int) -> list[list[int]]:
    result = [[1, 0], [0, 1]]
    while n:
        if n & 1:
            result = _mat_mul(result, m)
        m = _mat_mul(m, m)
        n >>= 1
    return result


def _mat_mul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    return [[(a[i][0] * b[0][j] + a[i][1] * b[1][j]) % MOD for j in range(2)] for i in range(2)]


def _comb_mod(n: int, k: int) -> int:
    """C(n, k) mod MOD for n < MOD, without building the exact integer."""
    k = min(k, n - k)
    num = den = 1
    for i in range(k):
        num = num * (n - i) % MOD
        den = den * (i + 1) % MOD
    return num * pow(den, -1, MOD) % MOD


def _modulo_note(level: int, threshold: int = 3) -> str:
    return f" Give the answer modulo {MOD}." if level >= threshold else ""


# -- generators --------------------------------------------------------------
# Each takes (level, rng) and returns (statement, answer).


def _crt(level: int, rng: random.Random) -> tuple[str, int]:
    count = (2, 3, 3, 4, 5)[level - 1]
    moduli = sorted({_prime_between(rng, 3, 10 ** (level + 1)) for _ in range(count)})
    product = math.prod(moduli)
    x = rng.randrange(1, product + 1)
    system = ", ".join(f"x ≡ {x % m} (mod {m})" for m in moduli)
    return f"Find the smallest positive integer x such that {system}.", x


def _sieve(level: int, rng: random.Random) -> tuple[str, int]:
    primes = sorted(rng.sample(SMALL_PRIMES, level + 1))
    n = rng.randrange(10 ** (level + 2), 10 ** (2 * level + 3))
    total = 0
    for size in range(len(primes) + 1):
        for subset in combinations(primes, size):
            total += (-1) ** size * (n // math.prod(subset))
    listed = ", ".join(map(str, primes))
    return (
        f"How many integers k with 1 ≤ k ≤ {n} are divisible by none of {listed}?",
        total,
    )


def _recurrence(level: int, rng: random.Random) -> tuple[str, int]:
    a0, a1 = rng.randrange(0, 10), rng.randrange(1, 10)
    c1, c2 = rng.randrange(1, 10), rng.randrange(1, 10)
    n = rng.randrange(10 ** (4 * level - 2), 10 ** (4 * level))
    m = _mat_pow([[c1, c2], [1, 0]], n - 1)
    value = (m[0][0] * a1 + m[0][1] * a0) % MOD
    return (
        f"A sequence has a(0) = {a0}, a(1) = {a1} and a(k) = {c1}·a(k-1) + {c2}·a(k-2)"
        f" for k ≥ 2. What is a({n}) modulo {MOD}?",
        value,
    )


def _lattice(level: int, rng: random.Random) -> tuple[str, int]:
    size = 10**level
    a, b = rng.randrange(size // 2, size + 1), rng.randrange(size // 2, size + 1)
    c, d = rng.randrange(1, a), rng.randrange(1, b)
    comb = math.comb if level < 3 else _comb_mod
    total = comb(a + b, a) - comb(c + d, c) * comb(a - c + b - d, a - c)
    if level >= 3:
        total %= MOD
    return (
        f"A lattice path from (0, 0) to ({a}, {b}) takes unit steps right or up."
        f" How many such paths do not pass through the point ({c}, {d})?" + _modulo_note(level),
        total,
    )


def _two_term(a: int, b: int, m: int) -> int:
    """Non-negative solutions (x, y) of a·x + b·y = m."""
    g = math.gcd(a, b)
    if m % g:
        return 0
    a, b, m = a // g, b // g, m // g
    y0 = m * pow(b, -1, a) % a
    return 0 if b * y0 > m else (m - b * y0) // (a * b) + 1


def _diophantine(level: int, rng: random.Random) -> tuple[str, int]:
    a, b, c = sorted(rng.sample(range(2, 4 + 3 * level), 3))
    n = rng.randrange(10 ** (level + 1), 2 * 10 ** (level + 1))
    count = sum(_two_term(a, b, n - c * z) for z in range(n // c + 1))
    return (
        f"How many triples (x, y, z) of non-negative integers satisfy {a}x + {b}y + {c}z = {n}?",
        count,
    )


def _power_sum(level: int, rng: random.Random) -> tuple[str, int]:
    e = rng.randrange(level + 1, level + 3)
    if level <= 2:
        n = rng.randrange(10 ** (2 * level - 1), 10 ** (2 * level + 1))
        value = sum(k**e for k in range(1, n + 1))
    else:
        n = rng.randrange(10 ** (4 * level - 3), 10 ** (4 * level))
        value = _power_sum_mod(n, e)
    return f"Compute the sum of k^{e} for k = 1, 2, ..., {n}." + _modulo_note(level), value


def _power_sum_mod(n: int, e: int) -> int:
    """sum k^e for k <= n, mod MOD, by Lagrange interpolation of a degree e+1 polynomial."""
    ys = [0]
    for k in range(1, e + 2):
        ys.append((ys[-1] + pow(k, e, MOD)) % MOD)
    x = n % MOD
    if x < len(ys):
        return ys[x]
    total = 0
    for i, y in enumerate(ys):
        num = den = 1
        for j in range(len(ys)):
            if j != i:
                num = num * (x - j) % MOD
                den = den * (i - j) % MOD
        total = (total + y * num * pow(den, -1, MOD)) % MOD
    return total


def _divisor_sum(level: int, rng: random.Random) -> tuple[str, int]:
    small = {1: 3, 2: 4, 3: 2, 4: 1, 5: 1}[level]
    factors: dict[int, int] = {}
    for p in rng.sample(SMALL_PRIMES[:10], small):
        factors[p] = rng.randrange(1, 4 if level <= 2 else 3)
    large = {1: 0, 2: 0, 3: 1, 4: 2, 5: 2}[level]
    band = {3: (10**3, 10**4), 4: (10**5, 10**6), 5: (10**8, 10**9)}.get(level, (0, 0))
    while len(factors) < small + large:
        factors[_prime_between(rng, *band)] = 1
    n = math.prod(p**k for p, k in factors.items())
    sigma = math.prod((p ** (k + 1) - 1) // (p - 1) for p, k in factors.items())
    return f"What is the sum of all positive divisors of {n}?", sigma


def _tower(level: int, rng: random.Random) -> tuple[str, int]:
    p = _prime_between(rng, 10 ** (level + 1), 10 ** (level + 2))
    a = rng.randrange(2, 100)
    b = rng.randrange(2, 10 * level + 3)
    c = rng.randrange(10 ** (3 * level - 2), 10 ** (3 * level))
    value = pow(a, pow(b, c, p - 1), p)
    note = f" ({p} is prime)" if level <= 3 else ""
    return f"Compute {a}^({b}^{c}) modulo {p}{note}.", value


GENERATORS: dict[str, Callable[[int, random.Random], tuple[str, int]]] = {
    "crt": _crt,
    "sieve": _sieve,
    "recurrence": _recurrence,
    "lattice": _lattice,
    "diophantine": _diophantine,
    "power_sum": _power_sum,
    "divisor_sum": _divisor_sum,
    "tower": _tower,
}


def generate(level: int, rng: random.Random | None = None, kind: str | None = None) -> Problem:
    if level not in LEVELS:
        raise ValueError(f"level must be 1..5, got {level}")
    rng = rng or random.SystemRandom()
    kind = kind or rng.choice(sorted(GENERATORS))
    statement, answer = GENERATORS[kind](level, rng)
    return Problem(kind=kind, level=level, statement=statement, answer=str(answer))
