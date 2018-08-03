//based on https://ed25519.cr.yp.to/python/sign.py

const ed25519 = require('./ed25519');
const fs = require('fs');
const assert = require('assert');
const readline = require('readline');

const rl = readline.createInterface({
  input: fs.createReadStream('./sign.input.txt'), // from https://ed25519.cr.yp.to/python/sign.input
  crlfDelay: Infinity
});

rl.on('line', (line) => {
	const x = line.split(':');
	const sk = Buffer.from(x[0].slice(0, 64), 'hex');
	const x2 = Buffer.from(x[2], 'hex');
	const m = x2;
	/*if(m.length < 1000) {
		console.log('skip', m.length);
		return;
	}*/

	const pk = ed25519.publickey(sk);
	assert.deepStrictEqual(pk.toString('hex'), x[1]);
	assert.deepStrictEqual([sk.toString('hex'), pk.toString('hex')], [x[0].slice(0, 64), x[0].slice(64)]);

	const s = ed25519.signature(m, sk, pk);
	ed25519.checkvalid(s, m, pk);
	assert.deepStrictEqual(x[3], Buffer.concat([s, x2]).toString('hex'));
	console.log('success', m.length);
});