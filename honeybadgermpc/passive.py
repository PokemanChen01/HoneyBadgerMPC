import asyncio
from .field import GF
from .polynomial import polynomialsOver
from .jubjub import Point
from .router import simple_router
import random


class NotEnoughShares(Exception):
    pass


class PassiveMpc(object):

    def __init__(self, sid, N, t, myid, send, recv, prog):
        # Parameters for passive secure MPC
        # Note: tolerates min(t,N-t) crash faults
        assert type(N) is int and type(t) is int
        assert t < N
        self.sid = sid
        self.N = N
        self.t = t
        self.myid = myid

        # send(j, o): sends object o to party j with (current sid)
        # recv(): returns (j, o) from party j
        self.send = send
        self.recv = recv

        # An Mpc program should only depend on common parameters,
        # and the values of opened shares. Opened shares will be
        # assigned an ID based on the order that share is encountered.
        # So the protocol must encounter the shares in the same order.
        self.prog = prog

        # Store deferreds representing SharedValues
        self._openings = []

        # Store opened shares until ready to reconstruct
        # shareid => { [playerid => share] }
        self._share_buffers = tuple([] for _ in range(N))

        self.Share = shareInContext(self)

        # Preprocessing elements
        filename = 'sharedata/test_zeros-%d.share' % (self.myid,)
        self._zeros = iter(self.read_shares(open(filename)))

        filename = 'sharedata/test_rand-%d.share' % (self.myid,)
        self._rands = iter(self.read_shares(open(filename)))

        filename = 'sharedata/test_triples-%d.share' % (self.myid,)
        self._triples = iter(self.read_shares(open(filename)))

        filename = 'sharedata/test_bits-%d.share' % (self.myid,)
        self._bits = iter(self.read_shares(open(filename)))

    def _reconstruct(self, shareid):
        # Are there enough shares to reconstruct?
        shares = [(i+1, self._share_buffers[i][shareid])
                  for i in range(self.N)
                  if len(self._share_buffers[i]) > shareid]
        if len(shares) < self.t+1:
            raise NotEnoughShares

        # print('[%d] reconstruct %s' % (self.myid, shareid,))

        s = Poly.interpolate_at(shares)

        # Set the result on the future representing this share
        self._openings[shareid].set_result(s)

    def open_share(self, share):
        opening = asyncio.Future()
        shareid = len(self._openings)
        self._openings.append(opening)

        # Broadcast share
        for j in range(self.N):
            self.send(j, (shareid, share.v))

        # Reconstruct if we already had enough shares
        try:
            self._reconstruct(shareid)
        except NotEnoughShares:
            pass

        # Return future
        return opening

    def get_triple(self):
        a = next(self._triples)
        b = next(self._triples)
        ab = next(self._triples)
        return a, b, ab

    def get_rand(self):
        return next(self._rands)

    def get_zero(self):
        return next(self._zeros)

    def get_bit(self):
        return next(self._bits)

    async def _run(self):
        # Run receive loop as background task, until self.prog finishes
        loop = asyncio.get_event_loop()
        bgtask = loop.create_task(self._recvloop())
        res = await self.prog(self)
        bgtask.cancel()
        return res

    async def _recvloop(self):
        while True:
            (j, (shareid, share)) = await self.recv()
            buf = self._share_buffers[j]

            # Shareid is redundant, but confirm it is one greater
            assert shareid == len(buf)
            buf.append(share)

            # Reconstruct if we now have enough shares,
            # and if the opening has been asked for
            if len(self._openings) > shareid:
                try:
                    self._reconstruct(shareid)
                except NotEnoughShares:
                    pass

        return True

    # File I/O
    def read_shares(self, f):
        # Read shares from a file object
        lines = iter(f)
        # first line: field modulus
        modulus = int(next(lines))
        assert Field.modulus == modulus
        # second line: share degree
        degree = int(next(lines))   # noqa
        # third line: id
        myid = int(next(lines))     # noqa
        shares = []
        # remaining lines: shared values
        for line in lines:
            shares.append(self.Share(int(line)))
        return shares

    def write_shares(self, f, shares):
        write_shares(f, Field.modulus, self.myid,
                     [share.v for share in shares])


def write_shares(f, modulus, degree, myid, shares):
    print(modulus, file=f)
    print(degree, file=f)
    print(myid, file=f)
    for share in shares:
        print(share.value, file=f)

###############
# Share class
###############


def shareInContext(context):
    class Share(object):
        def __init__(self, v):
            # v is the local value of the share
            if type(v) is int:
                v = Field(v)
            assert type(v) is Field
            self.v = v

        # Publicly reconstruct a shared value
        def open(self):
            return context.open_share(self)

        # Linear combinations of shares can be computed directly
        # TODO: add type checks for the operators
        # @typecheck(Share)
        def __add__(self, other): return Share(self.v + other.v)

        def __sub__(self, other): return Share(self.v - other.v)

        def __radd__(self, other): return Share(self.v + other.v)

        def __rsub__(self, other): return Share(-self.v + other.v)

        # @typecheck(int,field)
        def __rmul__(self, other): return Share(self.v * other)

        # @typecheck(Share)
        # TODO
        def __mul__(self, other): raise NotImplemented

        def __str__(self): return '{%d}' % (self.v)

    return Share

# Share = shareInContext(None)


# Create a fake network with N instances of the program
async def runProgramInNetwork(program, N, t):
    loop = asyncio.get_event_loop()
    sends, recvs = simple_router(N)

    tasks = []
    # bgtasks = []
    for i in range(N):
        context = PassiveMpc('sid', N, t, i, sends[i], recvs[i], program)
        tasks.append(loop.create_task(context._run()))

    results = await asyncio.gather(*tasks)
    return results

#######################
# Generating test files
#######################

# Fix the field for now
Field = GF(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
Poly = polynomialsOver(Field)

security_parameter = 32


def write_polys(prefix, modulus, N, t, polys):
    for i in range(N):
        shares = [f(i+1) for f in polys]
        with open('%s-%d.share' % (prefix, i), 'w') as f:
            write_shares(f, modulus, t, i, shares)


def generate_test_triples(prefix, k, N, t):
    # Generate k triples, store in files of form "prefix-%d.share"
    polys = []
    for j in range(k):
        a = Field(random.randint(0, Field.modulus-1))
        b = Field(random.randint(0, Field.modulus-1))
        c = a*b
        polys.append(Poly.random(t, a))
        polys.append(Poly.random(t, b))
        polys.append(Poly.random(t, c))
    write_polys(prefix, Field.modulus, N, t, polys)


def generate_test_zeros(prefix, k, N, t):
    polys = []
    for j in range(k):
        polys.append(Poly.random(t, 0))
    write_polys(prefix, Field.modulus, N, t, polys)


def generate_test_randoms(prefix, k, N, t):
    polys = []
    for j in range(k):
        polys.append(Poly.random(t))
    write_polys(prefix, Field.modulus, N, t, polys)


def generate_test_bits(prefix, k, N, t):
    polys = []
    for j in range(k):
        bit = random.randint(0, 1)
        polys.append(Poly.random(t, bit))
    # print("``` poly ```", polys)
    write_polys(prefix, Field.modulus, N, t, polys)


###############
# Test programs
###############
async def test_prog1(context):

    # Example of Beaver multiplication
    x = context.get_zero() + context.Share(10)
    # x = context.Share(10)
    y = context.get_zero() + context.Share(15)
    # y = context.Share(15)

    a, b, ab = context.get_triple()
    # assert await a.open() * await b.open() == await ab.open()

    D = await (x - a).open()
    E = await (y - b).open()

    # This is a random share of x*y
    xy = context.Share(D*E) + D*b + E*a + ab

    X, Y, XY = await x.open(), await y.open(), await xy.open()
    assert X * Y == XY

    print("[%d] Finished" % (context.myid,), X, Y, XY)


# Read zeros from file, open them
async def test_prog2(context):

    shares = [context.get_zero() for _ in range(1000)]
    for share in shares[:100]:
        s = await share.open()
        assert s == 0
    print('[%d] Finished' % (context.myid,))


async def beaver_mult(context, x, y, a, b, ab):
    D = await (x - a).open()
    E = await (y - b).open()

    # This is a random share of x*y
    xy = context.Share(D*E) + D*b + E*a + ab

    return context.Share(await xy.open())


async def test_prog3(context):

    def mul(x, y):
        a, b, ab = context.get_triple()
        return beaver_mult(context, x, y, a, b, ab)

    # Stream of random numbers for taking inverses
    async def inverse(x):
        _r = context.get_rand()
        # return [r] / open([r * x])
        rx = await (await mul(_r, x)).open()
        return (1/rx) * _r

    # curve = Jubjub(Field(-1), d)

    P = Point(Field(0x18ea85ca00cb9d895cb7b8669baa263fd270848f90ebefabe95b38300e80bde1), Field(0x255fa75b6ef4d4e1349876df94ca8c9c3ec97778f89c0c3b2e4ccf25fdf9f7c1))
    Q = Point(Field(0x1624451837683b2c4d2694173df71c9174ffcc613788eef3a9c7a7d0011476fa), Field(0x6f76dbfd7c62860d59f5937fa66d0571158ff68f28ccd83a4cd41b9918ee8fe2))

    R = P + Q

    x1 = context.get_zero() + context.Share(P.x)
    y1 = context.get_zero() + context.Share(P.y)
    x2 = context.get_zero() + context.Share(Q.x)
    y2 = context.get_zero() + context.Share(Q.y)

    dx1x2y1y2 = P.curve.d * await mul(await mul(x1, x2), await mul(y1, y2))
    x3num = (await mul(x1, y2) + await mul(y1, x2))
    x3den = (context.Share(1) + dx1x2y1y2)
    x3 = await mul(x3num, await inverse(x3den))
    y3num = (await mul(y1, y2) + await mul(x1, x2))
    y3den = (context.Share(1) - dx1x2y1y2)
    y3 = await mul(y3num, await inverse(y3den))

    X3, Y3 = await x3.open(), await y3.open()

    assert X3 == R.x and Y3 == R.y


async def single_add(context, p, q):
    def mul(x, y):
        a, b, ab = context.get_triple()
        return beaver_mult(context, x, y, a, b, ab)

    # Stream of random numbers for taking inverses
    async def inverse(x):
        _r = context.get_rand()
        # return [r] / open([r * x])
        rx = await (await mul(_r, x)).open()
        return (1/rx) * _r

    x1 = context.get_zero() + context.Share(p.x)
    y1 = context.get_zero() + context.Share(p.y)
    x2 = context.get_zero() + context.Share(q.x)
    y2 = context.get_zero() + context.Share(q.y)

    dx1x2y1y2 = p.curve.d * await mul(await mul(x1, x2), await mul(y1, y2))
    x3num = (await mul(x1, y2) + await mul(y1, x2))
    x3den = (context.Share(1) + dx1x2y1y2)
    x3 = await mul(x3num, await inverse(x3den))
    y3num = (await mul(y1, y2) + await mul(x1, x2))
    y3den = (context.Share(1) - dx1x2y1y2)
    y3 = await mul(y3num, await inverse(y3den))

    X3, Y3 = await x3.open(), await y3.open()

    return Point(X3, Y3)


async def test_jubjub_add(context):
    P = Point(Field(0x18ea85ca00cb9d895cb7b8669baa263fd270848f90ebefabe95b38300e80bde1), Field(0x255fa75b6ef4d4e1349876df94ca8c9c3ec97778f89c0c3b2e4ccf25fdf9f7c1))
    Q = Point(Field(0x1624451837683b2c4d2694173df71c9174ffcc613788eef3a9c7a7d0011476fa), Field(0x6f76dbfd7c62860d59f5937fa66d0571158ff68f28ccd83a4cd41b9918ee8fe2))

    result = await single_add(context, P, Q)
    print("P + Q: ", result.x, result.y)


async def unbounded_fan_in_and(context, a):
    length = len(a)
    A = context.Share(1)
    for i in a:
        A = A + i


async def equality(context, p_share, q_share):

    def legendre_mod_p(a):
        """Return the legendre symbol ``legendre(a, p)`` where *p* is the
        order of the field of *a*.
        """

        assert a.modulus % 2 == 1
        b = (a ** ((a.modulus - 1)//2))
        if b == 1:
            return 1
        elif b == a.modulus-1:
            return -1
        return 0

    diff_a = p_share - q_share
    k = security_parameter

    def mul(x, y):
        a, b, ab = context.get_triple()
        return beaver_mult(context, x, y, a, b, ab)

    async def _gen_test_bit():

        # b \in {0, 1}
        # _b \in {5, 1}, for p = 1 mod 8, s.t. (5/p) = -1
        # so _b = -4 * b + 5
        _b = (-4) * context.get_bit() + context.Share(5)
        _r = context.get_rand()
        _rp = context.get_rand()

        # c = a * r + b * rp * rp
        # If b_i == 1 c_i will always be a square modulo p if a is
        # zero and with probability 1/2 otherwise (except if rp == 0).
        # If b_i == -1 it will be non-square.
        _c = await mul(diff_a, _r) + await mul(_b, await mul(_rp, _rp))
        c = await _c.open()

        return c, _b

    async def gen_test_bit():
        cj, bj = await _gen_test_bit()
        while cj == 0:
            cj, bj = await _gen_test_bit()
        # bj.open() \in {5, 1}

        legendre = legendre_mod_p(cj)

        if legendre == 1:
            xj = (1 / Field(2)) * (bj + context.Share(1))
        elif legendre == -1:
            xj = (-1) * (1 / Field(2)) * (bj - context.Share(1))
        else:
            gen_test_bit()

        return xj

    x = [await gen_test_bit() for _ in range(k)]

    # Take the product (this is here the same as the "and") of all
    # the x'es
    while len(x) > 1:
        x.append(await mul(x.pop(0), x.pop(0)))

    return await x[0].open()


async def test_equality(context):
    p = context.get_zero() + context.Share(2333)
    q = context.get_zero() + context.Share(2333)
    
    result = await equality(context, p, q)

    if result == 0:
        print("The two numbers are different! (with high probability)")
    else:
        print("The two numbers are equal!")


async def comparison(context, p_share, q_share):
    pass


async def test_comparison(context):
    pass



# Run some test cases
if __name__ == '__main__':
    print('Generating random shares of zero in sharedata/')
    generate_test_zeros('sharedata/test_zeros', 1000, 3, 2)
    print('Generating random shares in sharedata/')
    generate_test_randoms('sharedata/test_rand', 1000, 3, 2)
    print('Generating random shares of triples in sharedata/')
    generate_test_triples('sharedata/test_triples', 1000, 3, 2)
    print('Generating random shares of bits in sharedata/')
    generate_test_bits('sharedata/test_bits', 1000, 3, 2)

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    try:
        loop.run_until_complete(runProgramInNetwork(test_prog1, 3, 2))
        loop.run_until_complete(runProgramInNetwork(test_prog2, 3, 2))
        loop.run_until_complete(runProgramInNetwork(test_prog3, 3, 2))
        loop.run_until_complete(runProgramInNetwork(test_jubjub_add, 3, 2))
        loop.run_until_complete(runProgramInNetwork(test_equality, 3, 2))

    finally:
        loop.close()
