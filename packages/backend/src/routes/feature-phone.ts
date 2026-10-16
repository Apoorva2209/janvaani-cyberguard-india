import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { buildFeaturePhoneReply } from '../feature-phone/sms-reply.js';
import { escapeXml, isValidTwilioSignature, smsResponse } from '../feature-phone/twilio.js';

/**
 * Webhooks that let people on feature (button) phones use JanVaani:
 *   POST /sms         - text a suspicious message in, get a verdict SMS back
 *   POST /voice       - phone menu for callers (keypad only)
 *   POST /voice/menu  - handles the digit pressed in the menu
 *
 * Built for Twilio-compatible telephony providers (form-encoded webhooks, TwiML replies).
 * The routes stay switched off until both settings exist:
 *   FEATURE_PHONE_AUTH_TOKEN  - provider auth token, used to verify webhook signatures
 *   FEATURE_PHONE_PUBLIC_URL  - public base URL of this API, e.g. https://api.example.in
 * Message text is never logged or stored.
 */

const BASE_PATH = '/api/v1/feature-phone';
const XML = 'text/xml; charset=utf-8';

const MENU_PROMPT_EN =
  'Welcome to JanVaani, your cyber safety helper. ' +
  'Press 1 to learn how to report cyber fraud. ' +
  'Press 2 for tips to stay safe from scams. ' +
  'Press 3 to hear this menu again.';

const REPORT_EN =
  'To report cyber fraud in India, dial 1 9 3 0 right away. ' +
  'The sooner you call after losing money, the better the chance of stopping the transfer. ' +
  'You can also report at cybercrime dot gov dot in. ' +
  'Keep your bank statement and the scammer phone number ready.';

const TIPS_EN =
  'Stay safe. Never share your OTP, UPI PIN, card number or Aadhaar with anyone, even if they say they are from the bank or police. ' +
  'No real officer asks for money to avoid arrest. ' +
  'Do not install apps that a caller asks you to install. ' +
  'If you feel pressure to act fast, stop, hang up, and call 1 9 3 0.';

type FormBody = Record<string, string>;

function say(text: string): string {
  return `<Say language="en-IN">${escapeXml(text)}</Say>`;
}

function voiceMenu(): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?><Response>' +
    `<Gather numDigits="1" timeout="6" action="${BASE_PATH}/voice/menu" method="POST">${say(MENU_PROMPT_EN)}</Gather>` +
    `${say('We did not receive any input. Goodbye.')}<Hangup/></Response>`
  );
}

function voiceAnswer(digit: string): string {
  const header = '<?xml version="1.0" encoding="UTF-8"?><Response>';
  if (digit === '1') return `${header}${say(REPORT_EN)}<Pause length="1"/>${say('Goodbye.')}<Hangup/></Response>`;
  if (digit === '2') return `${header}${say(TIPS_EN)}<Pause length="1"/>${say('Goodbye.')}<Hangup/></Response>`;
  return voiceMenu();
}

export async function featurePhoneRoutes(app: FastifyInstance): Promise<void> {
  const authToken = process.env.FEATURE_PHONE_AUTH_TOKEN;
  const publicUrl = process.env.FEATURE_PHONE_PUBLIC_URL?.replace(/\/+$/, '');

  // Telephony providers post application/x-www-form-urlencoded; parse it for this plugin only.
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string', bodyLimit: 16 * 1024 },
    (_req, body, done) => {
      try {
        done(null, Object.fromEntries(new URLSearchParams(body as string)));
      } catch (err) {
        done(err as Error, undefined);
      }
    },
  );

  /** Returns the parsed form body when the request is signed by the provider, otherwise null. */
  const verified = (request: FastifyRequest, path: string): FormBody | null => {
    if (!authToken || !publicUrl) return null;
    const body = (request.body ?? {}) as FormBody;
    const signature = request.headers['x-twilio-signature'];
    const ok = isValidTwilioSignature(
      authToken,
      `${publicUrl}${BASE_PATH}${path}`,
      body,
      typeof signature === 'string' ? signature : undefined,
    );
    return ok ? body : null;
  };

  const reject = (reply: FastifyReply) => reply.code(403).send({ error: 'Invalid signature' });

  if (!authToken || !publicUrl) {
    app.log.info('Feature phone routes are disabled (FEATURE_PHONE_AUTH_TOKEN / FEATURE_PHONE_PUBLIC_URL not set).');
  }

  app.post('/sms', async (request, reply) => {
    const body = verified(request, '/sms');
    if (!body) return reject(reply);
    const { text } = buildFeaturePhoneReply(typeof body.Body === 'string' ? body.Body : '');
    return reply.type(XML).send(smsResponse(text));
  });

  app.post('/voice', async (request, reply) => {
    if (!verified(request, '/voice')) return reject(reply);
    return reply.type(XML).send(voiceMenu());
  });

  app.post('/voice/menu', async (request, reply) => {
    const body = verified(request, '/voice/menu');
    if (!body) return reject(reply);
    return reply.type(XML).send(voiceAnswer(typeof body.Digits === 'string' ? body.Digits : ''));
  });
}
