/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  encode as _encode,
  decode as _decode
} from './baseN.js';

// base58 characters (Bitcoin alphabet)
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(input, maxline) {
  return _encode(input, alphabet, maxline);
}

export function base58Decode(input) {
  return _decode(input, alphabet);
}