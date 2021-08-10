import crypto from 'crypto';
import { AES_CIPHER } from './constants';

export const encrypt = (text, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AES_CIPHER, key, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return `${iv.toString('hex')}${encrypted.toString('hex')}`;
};

export const checkIsTrue = (result, message) => {
  if (result !== true) throw new Error(message);
};

export const checkStringDifferent = (value1, value2, message) => {
  if (value1 === value2) throw new Error(message);
};
