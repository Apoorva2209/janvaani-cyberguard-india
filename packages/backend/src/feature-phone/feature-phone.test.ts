import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildFeaturePhoneReply, extractUrls, fitToSms } from './sms-reply.js';
import { escapeXml, isValidTwilioSignature, smsResponse } from './twilio.js';

describe('feature phone SMS reply', () => {
  it('warns about a UPI PIN request', () => {
    const reply = buildFeaturePhoneReply('Enter your UPI PIN to receive money');
    expect(reply.verdict).not.toBe('NO_FLAGS');
    expect(reply.text).toContain('1930');
  });

  it('does not raise an alarm for an ordinary message', () => {
    const reply = buildFeaturePhoneReply('Your library book is due next week.');
    expect(reply.verdict).toBe('NO_FLAGS');
    expect(reply.text.toLowerCase()).toContain('not proof');
  });

  it('answers help requests with instructions', () => {
    expect(buildFeaturePhoneReply('help').text).toContain('JanVaani');
    expect(buildFeaturePhoneReply('   ').text).toContain('JanVaani');
  });

  it('keeps every reply inside a single 160-character ASCII SMS', () => {
    for (const body of ['Enter your UPI PIN to receive money', 'hello there', 'help', 'CBI officer says digital arrest']) {
      const { text } = buildFeaturePhoneReply(body);
      expect(text.length).toBeLessThanOrEqual(160);
      expect(/^[\x20-\x7E]+$/.test(text)).toBe(true);
    }
  });

  it('truncates overly long text with an ellipsis', () => {
    const out = fitToSms('x'.repeat(400));
    expect(out).toHaveLength(160);
    expect(out.endsWith('...')).toBe(true);
  });

  it('extracts links from free text', () => {
    expect(extractUrls('Claim now at http://bit-rewards.top/claim, thanks')).toEqual([
      'http://bit-rewards.top/claim',
    ]);
  });
});

describe('Twilio webhook helpers', () => {
  // Random per run, so no key is hardcoded in the repository.
  const token = crypto.randomBytes(16).toString('hex');
  const url = 'https://api.example.in/api/v1/feature-phone/sms';
  const params = { Body: 'hello', From: '+910000000000' };
  const sign = (u: string, p: Record<string, string>) =>
    crypto
      .createHmac('sha1', token)
      .update(Object.keys(p).sort().reduce((acc, k) => acc + k + p[k], u))
      .digest('base64');

  it('accepts a correctly signed request', () => {
    expect(isValidTwilioSignature(token, url, params, sign(url, params))).toBe(true);
  });

  it('rejects a missing, wrong or tampered signature', () => {
    expect(isValidTwilioSignature(token, url, params, undefined)).toBe(false);
    expect(isValidTwilioSignature(token, url, params, 'not-a-signature')).toBe(false);
    expect(isValidTwilioSignature(token, url, { ...params, Body: 'changed' }, sign(url, params))).toBe(false);
  });

  it('escapes XML special characters in replies', () => {
    expect(escapeXml('a<b>&"c\'')).toBe('a&lt;b&gt;&amp;&quot;c&apos;');
    expect(smsResponse('1 < 2')).toContain('<Message>1 &lt; 2</Message>');
  });
});
