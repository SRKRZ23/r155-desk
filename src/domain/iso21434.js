/**
 * ISO/SAE 21434 risk calculation, kept free of any Forge code so it can be unit tested.
 *
 * The method follows the threat analysis and risk assessment (TARA) steps of ISO/SAE 21434 clause 15:
 *   1. Impact rating per category (Safety, Financial, Operational, Privacy). The overall impact is the worst one.
 *   2. Attack feasibility from the attack-potential approach (Annex G): five factors are scored and summed.
 *   3. Risk value 1..5 from a risk matrix (impact x feasibility).
 *
 * The factor scores, feasibility bands and risk matrix below are the example values given in the standard's
 * annexes. Organisations may tailor them, so they are exported and the functions accept overrides.
 */

/** Impact levels in ascending order of severity. */
export const IMPACT_LEVELS = ['negligible', 'moderate', 'major', 'severe'];

/** Impact categories rated separately (S, F, O, P). */
export const IMPACT_CATEGORIES = ['safety', 'financial', 'operational', 'privacy'];

/** Attack-potential factor scores (ISO/SAE 21434 Annex G, based on ISO/IEC 18045). */
export const ATTACK_POTENTIAL_FACTORS = {
  elapsedTime: { le1day: 0, le1week: 1, le1month: 4, le6months: 17, gt6months: 19 },
  expertise: { layman: 0, proficient: 3, expert: 6, multipleExperts: 8 },
  knowledge: { public: 0, restricted: 3, confidential: 7, strictlyConfidential: 11 },
  windowOfOpportunity: { unlimited: 0, easy: 1, moderate: 4, difficult: 10 },
  equipment: { standard: 0, specialized: 4, bespoke: 7, multipleBespoke: 9 },
};

/** Human labels for the factor options, used by the UI and by the agent's explanations. */
export const FACTOR_LABELS = {
  elapsedTime: { le1day: '≤ 1 day', le1week: '≤ 1 week', le1month: '≤ 1 month', le6months: '≤ 6 months', gt6months: '> 6 months' },
  expertise: { layman: 'Layman', proficient: 'Proficient', expert: 'Expert', multipleExperts: 'Multiple experts' },
  knowledge: { public: 'Public', restricted: 'Restricted', confidential: 'Confidential', strictlyConfidential: 'Strictly confidential' },
  windowOfOpportunity: { unlimited: 'Unlimited', easy: 'Easy', moderate: 'Moderate', difficult: 'Difficult' },
  equipment: { standard: 'Standard', specialized: 'Specialized', bespoke: 'Bespoke', multipleBespoke: 'Multiple bespoke' },
};

/**
 * Attack feasibility bands by summed attack potential (Annex G example):
 * 0-9 High, 10-13 Medium, 14-19 Low, 20+ Very low. A low attack potential means an easy attack.
 */
export const FEASIBILITY_BANDS = [
  { max: 9, level: 'high' },
  { max: 13, level: 'medium' },
  { max: 19, level: 'low' },
  { max: Infinity, level: 'veryLow' },
];

export const FEASIBILITY_LEVELS = ['veryLow', 'low', 'medium', 'high'];

/** Risk matrix (Annex H example): RISK_MATRIX[impact][feasibility] -> risk value 1..5. */
export const RISK_MATRIX = {
  severe: { veryLow: 2, low: 3, medium: 4, high: 5 },
  major: { veryLow: 1, low: 2, medium: 3, high: 4 },
  moderate: { veryLow: 1, low: 2, medium: 2, high: 3 },
  negligible: { veryLow: 1, low: 1, medium: 1, high: 1 },
};

/**
 * Response policy per risk value. This is NOT part of the standard: it is the organisation's own
 * cybersecurity incident response policy, shown here with sensible defaults that an admin can change.
 */
export const DEFAULT_RESPONSE_POLICY = {
  5: { treatment: 'reduce', triageDays: 1, remediationDays: 14, label: 'Critical' },
  4: { treatment: 'reduce', triageDays: 2, remediationDays: 30, label: 'High' },
  3: { treatment: 'reduce', triageDays: 5, remediationDays: 90, label: 'Medium' },
  2: { treatment: 'retain or reduce', triageDays: 10, remediationDays: 180, label: 'Low' },
  1: { treatment: 'retain', triageDays: 20, remediationDays: null, label: 'Very low' },
};

/**
 * True once the analyst has rated at least one impact category. Until then there is no risk value:
 * showing "1/5" for an unrated report would make an unreviewed issue look safe.
 */
export function isImpactRated(impacts = {}) {
  return IMPACT_CATEGORIES.some((c) => IMPACT_LEVELS.includes(impacts?.[c]));
}

/** Returns the worst impact level across the four categories. Unknown or missing values count as negligible. */
export function overallImpact(impacts = {}) {
  let worst = 0;
  for (const category of IMPACT_CATEGORIES) {
    const index = IMPACT_LEVELS.indexOf(impacts[category]);
    if (index > worst) worst = index;
  }
  return IMPACT_LEVELS[worst];
}

/**
 * Sums the attack-potential factors. Throws on an unknown option so a typo can never silently
 * produce an "easy" attack (a missing factor would otherwise score 0 and inflate feasibility).
 */
export function attackPotential(factors = {}, table = ATTACK_POTENTIAL_FACTORS) {
  let total = 0;
  for (const [factor, options] of Object.entries(table)) {
    const choice = factors[factor];
    if (!(choice in options)) {
      throw new Error(`Unknown or missing value for ${factor}: ${choice}. Allowed: ${Object.keys(options).join(', ')}`);
    }
    total += options[choice];
  }
  return total;
}

/** Maps a summed attack potential to a feasibility level. */
export function feasibilityFromPotential(potential, bands = FEASIBILITY_BANDS) {
  return bands.find((band) => potential <= band.max).level;
}

/**
 * Full assessment. `discoveredAt` is an ISO date string; deadlines are computed from it.
 * Returns everything the UI, the agent and the audit trail need, including the reasoning.
 */
export function assessRisk({ impacts, factors, discoveredAt, policy = DEFAULT_RESPONSE_POLICY }) {
  const impact = overallImpact(impacts);
  const potential = attackPotential(factors);
  const feasibility = feasibilityFromPotential(potential);
  const riskValue = RISK_MATRIX[impact][feasibility];
  const response = policy[riskValue];

  const start = discoveredAt ? new Date(discoveredAt) : new Date();
  const addDays = (days) => (days == null ? null : new Date(start.getTime() + days * 86400000).toISOString().slice(0, 10));

  const worstCategories = IMPACT_CATEGORIES.filter((c) => impacts?.[c] === impact && impact !== 'negligible');

  return {
    impact,
    worstCategories,
    attackPotential: potential,
    feasibility,
    riskValue,
    riskLabel: response.label,
    treatment: response.treatment,
    triageDue: addDays(response.triageDays),
    remediationDue: addDays(response.remediationDays),
    explanation:
      `Impact ${impact}${worstCategories.length ? ` (${worstCategories.join(', ')})` : ''}; ` +
      `attack potential ${potential} → feasibility ${feasibility}; ` +
      `risk matrix gives ${riskValue}/5 (${response.label}).`,
  };
}
