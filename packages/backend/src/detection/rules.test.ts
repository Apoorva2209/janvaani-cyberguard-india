import { describe, expect, it } from 'vitest';
import { DeterministicRuleEngine } from './rules.js';

describe('DeterministicRuleEngine', () => {
  const engine = new DeterministicRuleEngine();

  it('flags a UPI PIN request framed as receiving money', () => {
    const matches = engine.evaluate('Enter your UPI PIN to receive money');

    expect(matches.some((match) => match.category === 'UPI_FRAUD')).toBe(true);
  });

  it('does not invent a match for an ordinary library reminder', () => {
    expect(engine.evaluate('Your library book is due next week.')).toEqual([]);
  });

  it('flags a punycode lookalike domain as suspicious', () => {
    const matches = engine.evaluate('', ['https://xn--e1afmkfd.test']);

    expect(matches.some((match) => match.ruleId === 'IND-HOMOGRAPH-001')).toBe(true);
  });

  it('returns indicators, not a real-world sender identity', () => {
    const matches = engine.evaluate('CBI officer says digital arrest');

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]).not.toHaveProperty('senderIdentity');
  });
});
