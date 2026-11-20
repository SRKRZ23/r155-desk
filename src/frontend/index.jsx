/**
 * "R155 Assessment" issue panel (UI Kit).
 *
 * Flow: the panel reads the issue, detects the software component named in it, shows the blast radius
 * (which ECUs and vehicle lines run that component, and how many vehicles are in the field), lets the
 * analyst rate impact and attack potential, and computes the ISO/SAE 21434 risk value live. Saving
 * stores the assessment on the issue (recomputed on the server).
 *
 * The risk maths is imported directly from the shared domain module, so live recalculation needs no
 * backend call (cheaper and instant). Only reading the issue and saving go through the resolver.
 */
import React, { useEffect, useMemo, useState } from 'react';
import ForgeReconciler, {
  Box, Button, DynamicTable, Heading, Inline, Label, Lozenge, SectionMessage, Select, Spinner, Stack, Strong, Text, Textfield,
} from '@forge/react';
import { invoke } from '@forge/bridge';
import { assessRisk, ATTACK_POTENTIAL_FACTORS, FACTOR_LABELS, IMPACT_CATEGORIES, IMPACT_LEVELS } from '../domain/iso21434.js';
import { DEMO_INVENTORY, findAffectedAssets } from '../domain/inventory.js';

const FACTOR_TITLES = {
  elapsedTime: 'Elapsed time', expertise: 'Specialist expertise', knowledge: 'Knowledge of the item',
  windowOfOpportunity: 'Window of opportunity', equipment: 'Equipment',
};
const IMPACT_TITLES = { safety: 'Safety', financial: 'Financial', operational: 'Operational', privacy: 'Privacy' };
const RISK_APPEARANCE = { 5: 'removed', 4: 'removed', 3: 'moved', 2: 'inprogress', 1: 'success' };

// Defaults for a fresh assessment: the analyst changes what applies. Worst-case-leaning factor defaults
// (an easy attack) so an un-reviewed report never looks safer than it is.
const DEFAULT_FACTORS = { elapsedTime: 'le1week', expertise: 'proficient', knowledge: 'public', windowOfOpportunity: 'easy', equipment: 'standard' };
const DEFAULT_IMPACTS = { safety: 'negligible', financial: 'negligible', operational: 'negligible', privacy: 'negligible' };

const componentOptions = [...new Set(DEMO_INVENTORY.ecus.flatMap((e) => e.components.map((c) => c.name)))]
  .sort()
  .map((name) => ({ label: name, value: name }));

const optionFor = (options, value) => options.find((o) => o.value === value) || null;

const App = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [issue, setIssue] = useState(null);
  const [component, setComponent] = useState('');
  const [affectedVersions, setAffectedVersions] = useState('');
  const [impacts, setImpacts] = useState(DEFAULT_IMPACTS);
  const [factors, setFactors] = useState(DEFAULT_FACTORS);
  const [saved, setSaved] = useState(null);
  const [saving, setSaving] = useState(false);

  // Load the issue and any saved assessment once.
  useEffect(() => {
    invoke('loadPanel')
      .then(({ issue: loadedIssue, detected, saved: savedValue }) => {
        setIssue(loadedIssue);
        const current = savedValue?.current;
        if (current) {
          setComponent(current.component);
          setAffectedVersions(current.affectedVersions || '');
          setImpacts({ ...DEFAULT_IMPACTS, ...current.impacts });
          setFactors({ ...DEFAULT_FACTORS, ...current.factors });
          setSaved(current);
        } else if (detected.length) {
          setComponent(detected[0].component);
          setAffectedVersions(detected[0].affectedVersions);
        }
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }, []);

  const discoveredAt = saved?.discoveredAt || issue?.created?.slice(0, 10);
  const result = useMemo(() => {
    try {
      return assessRisk({ impacts, factors, discoveredAt });
    } catch (e) {
      return { error: e.message };
    }
  }, [impacts, factors, discoveredAt]);
  const blast = useMemo(() => (component ? findAffectedAssets({ component, affectedVersions }) : null), [component, affectedVersions]);

  const onSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const value = await invoke('saveAssessment', { component, affectedVersions, impacts, factors, discoveredAt });
      setSaved(value.current);
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <Spinner label="Loading assessment" />;

  const ecuRows = (blast?.ecus || []).map((e) => ({
    key: `${e.ecuId}-${e.component}`,
    cells: [
      { key: 'ecu', content: e.ecuName },
      { key: 'ver', content: e.installedVersion },
      { key: 'aff', content: <Lozenge appearance={e.affected ? 'removed' : 'success'}>{e.affected ? 'Affected' : 'Not affected'}</Lozenge> },
      { key: 'lines', content: e.vehicleLines.join(', ') },
      { key: 'if', content: e.interfaces.join(', ') },
    ],
  }));

  return (
    <Stack space="space.200">
      {error && <SectionMessage appearance="error"><Text>{error}</Text></SectionMessage>}

      <Heading size="small">1. Affected component</Heading>
      <Inline space="space.200" alignBlock="end">
        <Box xcss={{ width: '55%' }}>
          <Label labelFor="component">Component</Label>
          <Select id="component" options={componentOptions} value={optionFor(componentOptions, component)} onChange={(o) => setComponent(o?.value || '')} />
        </Box>
        <Box xcss={{ width: '40%' }}>
          <Label labelFor="versions">Affected versions (e.g. &lt;3.0.8)</Label>
          <Textfield id="versions" value={affectedVersions} onChange={(e) => setAffectedVersions(e.target.value)} />
        </Box>
      </Inline>

      {blast && (
        <Stack space="space.100">
          <Text>
            <Strong>{blast.affectedEcuCount} affected ECU(s)</Strong> in {blast.vehicleLines.length} vehicle line(s) ·{' '}
            <Strong>{blast.fleetExposure.toLocaleString('en-US')} vehicles</Strong> in the field · markets: {blast.markets.join(', ') || 'none'}
          </Text>
          <DynamicTable
            head={{ cells: ['ECU', 'Installed', 'Status', 'Vehicle lines', 'Interfaces'].map((c) => ({ key: c, content: c })) }}
            rows={ecuRows}
            emptyView="This component is not in the inventory."
          />
        </Stack>
      )}

      <Heading size="small">2. Impact (ISO/SAE 21434 · S/F/O/P)</Heading>
      <Inline space="space.150" shouldWrap>
        {IMPACT_CATEGORIES.map((c) => {
          const options = IMPACT_LEVELS.map((l) => ({ label: l, value: l }));
          return (
            <Box key={c} xcss={{ width: '23%' }}>
              <Label labelFor={`impact-${c}`}>{IMPACT_TITLES[c]}</Label>
              <Select id={`impact-${c}`} options={options} value={optionFor(options, impacts[c])} onChange={(o) => setImpacts({ ...impacts, [c]: o.value })} />
            </Box>
          );
        })}
      </Inline>

      <Heading size="small">3. Attack potential (Annex G)</Heading>
      <Inline space="space.150" shouldWrap>
        {Object.keys(ATTACK_POTENTIAL_FACTORS).map((f) => {
          const options = Object.entries(FACTOR_LABELS[f]).map(([value, label]) => ({ value, label: `${label} (${ATTACK_POTENTIAL_FACTORS[f][value]})` }));
          return (
            <Box key={f} xcss={{ width: '31%' }}>
              <Label labelFor={`factor-${f}`}>{FACTOR_TITLES[f]}</Label>
              <Select id={`factor-${f}`} options={options} value={optionFor(options, factors[f])} onChange={(o) => setFactors({ ...factors, [f]: o.value })} />
            </Box>
          );
        })}
      </Inline>

      <Heading size="small">4. Risk</Heading>
      {result.error ? (
        <SectionMessage appearance="warning"><Text>{result.error}</Text></SectionMessage>
      ) : (
        <Stack space="space.100">
          <Inline space="space.100" alignBlock="center">
            <Lozenge appearance={RISK_APPEARANCE[result.riskValue]} isBold>{`Risk ${result.riskValue}/5 · ${result.riskLabel}`}</Lozenge>
            <Text>Treatment: {result.treatment}</Text>
          </Inline>
          <Text>{result.explanation}</Text>
          <Text>
            Triage due <Strong>{result.triageDue}</Strong>
            {result.remediationDue ? <> · remediation due <Strong>{result.remediationDue}</Strong></> : ' · no remediation deadline (risk retained)'}
          </Text>
        </Stack>
      )}

      <Inline space="space.200" alignBlock="center">
        <Button appearance="primary" onClick={onSave} isDisabled={!component || !!result.error || saving}>
          {saving ? 'Saving…' : 'Save assessment'}
        </Button>
        {saved && <Text>Last saved {saved.savedAt.slice(0, 16).replace('T', ' ')} UTC</Text>}
      </Inline>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
