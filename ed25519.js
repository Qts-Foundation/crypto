// based on https://ed25519.cr.yp.to/python/ed25519.py

const assert = require('assert');
const crypto = require('crypto');

const b = 256n;
const b16z = new Array(Number(b >> 2n)).fill('0').join('');
const q = (2n ** 255n) - 19n;
const l = (2n ** 252n) + 27742317777372353535851937790883648493n;

function pmod(n, m) { // positive mod
	const r = n % m;
	if(r >= 0n) { return r; }
	return (r + m) % m;
}

function H(m) {
	const hash = crypto.createHash('sha512');
	hash.update(m);
	const ret = hash.digest();
	return ret;
}

function expmod(b, e, m) {
  if(e == 0n) {
		return 1n;
	}

	let t = pmod((expmod(b, e / 2n, m) ** 2n), m);
  if(e & 1n) {
		t = pmod((t * b), m);
	}

  return t
}

function inv(x) {
	return expmod(x, q - 2n, q);
}

const d = -121665n * inv(121666n);

const I = expmod(2n, (q - 1n) / 4n, q);

function xrecover(y) {
  const xx = (y * y - 1n) * inv(d * y * y + 1n);
  let x = expmod(xx, (q + 3n) / 8n,q);
  if(pmod((x * x - xx), q) !== 0n) {
		x = pmod((x * I), q);
	}
  if(pmod(x, 2n) !== 0n) {
		x = q - x;
	}
	return x
}

const By = 4n * inv(5n);
const Bx = xrecover(By);
const B = [pmod(Bx, q), pmod(By, q)];

function edwards(P, Q) {
	const x1 = P[0];
  const y1 = P[1];
  const x2 = Q[0];
  const y2 = Q[1];
  const x3 = (x1 * y2 + x2 * y1) * inv(1n + d * x1 * x2 * y1 * y2);
	const y3 = (y1 * y2 + x1 * x2) * inv(1n - d * x1 * x2 * y1 * y2);
	const x4 = pmod(x3, q);
	const y4 = pmod(y3, q);
	return [x4, y4];
}

function scalarmult(P, e) {
  if(e === 0n) {
		return [0n, 1n];
	}

	let Q = scalarmult(P, e / 2n);
	Q = edwards(Q, Q);
	
	if(e & 1n) {
		Q = edwards(Q, P);
	}

	return Q;
}

function range(r) {
	const ret = [];
	for(let i = 0n; i < r; i++) {
		ret[i] = i;
	}
	return ret;
}

function range2(s, e) {
	const ret = [];
	for(let i = s; i < e; i++) {
		ret[ret.length] = i;
	}
	return ret;
}

function encodeint(y) {
	const bits = range(b).map((v)=> (y >> v) & 1n);
	const r = Buffer.from(range(b / 8n).map((i)=> Number(sum( range(8n).map((j)=> bits[i * 8n + j] << j)))));
	assert.deepStrictEqual(y, decodeint(r));
	return r;
}

function sum(n) {
	return n.reduce((p, c)=> p + c);
}

function encodepoint(P) {
	const x = P[0];
	const y = P[1];
	const bits = range(b - 1n).map((v)=> (y >> v) & 1n);
	bits.push(x & 1n);
	const r = Buffer.from(range(b / 8n).map((i)=> Number(sum( range(8n).map((j)=> bits[i * 8n + j] << j)))));
	assert.deepStrictEqual(decodepoint(r), P);
	return r;
}

function bit(h,i) {
	return (BigInt(h[i / 8n]) >> (i % 8n)) & 1n;
}

function publickey(sk) {
	h = H(sk);
	let a = 2n ** (b - 2n);
	range2(3n, b - 2n).forEach((v, i, arr) => {
		const bitn = bit(h, v);
		a += 2n ** v * bitn;
	});
  A = scalarmult(B, a);
	return encodepoint(A);
}

function Hint(m) {
	h = H(m);
	let r = 0n;
	range(2n * b).forEach((v, i, a)=> {
		r += 2n ** v * bit(h, v);
	});
	return r;
}


function signature(m, sk, pk) {
	h = H(sk);

	let a = 2n ** (b - 2n);
	range2(3n, b - 2n).forEach((v, i)=> {
		a += 2n ** v * bit(h, v);
	});

	const r = Hint(Buffer.concat([h.slice(Number(b / 8n), Number(b / 4n)), m]));
	const R = scalarmult(B, r);
	const ep = encodepoint(R);
	const preHint = Buffer.concat([ep, pk, m]);
	const postHint = Hint(preHint);
	S = pmod((r + postHint * a), l);

	const ret = Buffer.concat([encodepoint(R), encodeint(S)])
	return ret;
}

function isoncurve(P) {
  const x = P[0];
  const y = P[1];
	return pmod((-x * x + y * y - 1n - d * x * x * y * y), q) === 0n;
}

function decodeint(s) {
	const y = sum(range(b).map((i)=> 2n**i * bit(s, i)));
	return y;
}

function decodepoint(s) {
	const y = sum(range(b - 1n).map((i)=> 2n**i * bit(s, i)));
	let x = xrecover(y);
	
  if((x % 1n) !== bit(s, b - 1n)) {
		x = q - x;
	}
  P = [x,y]
  if(!isoncurve(P)) { throw new Error("decoding point that is not on curve"); }
	return P;
}

function checkvalid(s,m,pk) {
  if(s.length !== Number(b / 4n)) { throw new Error("signature length is wrong"); }
	if(pk.length !== Number(b / 8n)) { throw new Error("public-key length is wrong"); }
  const R = decodepoint(s.slice(0, Number(b/8n)));
  const A = decodepoint(pk);
  const S = decodeint(s.slice(Number(b/8n), Number(b/4n)));
	const h = Hint(Buffer.concat([encodepoint(R), pk, m]));
	
	const sm_bs = scalarmult(B,S);
	const e_r_sm_A_h = edwards(R,scalarmult(A,h));
  if(!((sm_bs[0] === e_r_sm_A_h[0]) && (sm_bs[1] === e_r_sm_A_h[1]))) {
		throw new Error("signature does not pass verification");
	}
}

module.exports = {b, H, expmod, q, l, d, I, B, isoncurve, scalarmult, publickey, signature, checkvalid};