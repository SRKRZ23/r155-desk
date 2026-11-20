/**
 * "R155 Assessment" issue panel (UI Kit).
 *
 * Flow: the panel reads the issue, detects the software component and the entry interface named in it,
 * shows the blast radius (which ECUs and vehicle lines run that component, how many vehicles are in the
 * field, and whether each ECU is reachable directly from the entry interface or only through other ECUs),
 * suggests attack-potential factors with reasons, lets the analyst rate impact, and computes the
 * ISO/SAE 21434 risk value live. Saving stores the assessment on the issue (recomputed on the server);
 * "Publish audit record" writes it to Confluence.
 *
 * The risk maths is imported from the shared domain module, so live recalculation needs no backend call.
 */
import React, { useEffect, useMemo, useState } from 'react';
import ForgeReconciler, {
  Box, Button, DynamicTable, Heading, Inline, Label, Link, Lozenge, SectionMessage, Select, Spinner, Stack, Strong, Text, Textfield,
} from '@forge/react';
import { invoke } from '@forge/bridge';
import { assessRisk, ATTACK_POTENTIAL_FACTORS, FACTOR_LABELS, IMPACT_CATEGORIES, IMPACT_LEVELS, isImpactRated } from '../domain/iso21434.js';
import { findAffectedAssets, INTERFACE_CLASSES, suggestFactors } from '../domain/inventory.js';

const FACTOR_TITLES = {
  elapsedTime: 'Elapsed time', expertise: 'Specialist expertise', knowledge: 'Knowledge of the item',
  windowOfOpportunity: 'Window of opportunity', equipment: 'Equipment',
};
const IMPACT_TITLES = { safety: 'Safety', financial: 'Financial', operational: 'Operational', privacy: 'Privacy' };
const RISK_APPEARANCE = { 5: 'removed', 4: 'removed', 3: 'moved', 2: 'inprogress', 1: 'success' };
const EXPOSURE_LOZENGE = {
  direct: { appearance: 'removed', text: 'Direct' },
  indirect: { appearance: 'moved', text: 'Via other ECUs' },
  none: { appearance: 'success', text: 'No path' },
  unknown: { appearance: 'default', text: 'Entry unknown' },
};
const interfaceOptions = INTERFACE_CLASSES.map((c) => ({ label: c.label, value: c.id }));
const impactOptions = IMPACT_LEVELS.map((l) => ({ label: l, value: l }));
const optionFor = (options, value) => options.find((o) => o.value === value) || null;
const EXPOSURE_RANK = { direct: 0, indirect: 1, unknown: 2, none: 3 };

const App = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [issue, setIssue] = useState(null);
  const [inventory, setInventory] = useState(null);
  const [component, setComponent] = useState('');
  const [affectedVersions, setAffectedVersions] = useState('');
  const [entry, setEntry] = useState([]);
  const [impacts, setImpacts] = useState({});
  const [factors, setFactors] = useState(null);
  const [saved, setSaved] = useState(null);
  const [busy, setBusy] = useState(null);
  const [confluenceSpaceKey, setConfluenceSpaceKey] = useState(null);

  useEffect(() => {
    invoke('loadPanel')
      .then((data) => {
        setIssue(data.issue);
        setInventory(data.inventory);
        setConfluenceSpaceKey(data.confluenceSpaceKey);
        const current = data.saved?.current;
        if (current) {
          setComponent(current.component);
          setAffectedVersions(current.affectedVersions || '');
          setEntry(current.reportedInterfaces || data.triage.reportedInterfaces);
          setImpacts(current.impacts || {});
          setFactors(current.factors);
          setSaved(current);
        } else {
          const first = data.triage.components[0];
          if (first) {
            setComponent(first.component);
            setAffectedVersions(first.affectedVersions.startsWith('not specified') ? '' : first.affectedVersions);
          }
          setEntry(data.triage.reportedInterfaces);
          setFactors(data.triage.suggestion.factors); // a starting point; the reasons are shown next to it
        }
      })
      .catch((e) => setError(e.message || String(e)))
      .finally(() => setLoading(false));
  }, []);

  const componentOptions = useMemo(
    () => [...new Set((inventory?.ecus || []).flatMap((e) => e.components.map((c) => c.name)))].sort().map((n) => ({ label: n, value: n })),
    [inventory],
  );
  const blast = useMemo(
    () => (component && inventory ? findAffectedAssets({ component, affectedVersions, reportedInterfaces: entry }, inventory) : null),
    [component, affectedVersions, entry, inventory],
  );
  const bestExposure = useMemo(() => {
    const kinds = (blast?.ecus || []).filter((e) => e.affected).map((e) => e.exposure.kind);
    return kinds.sort((a, b) => EXPOSURE_RANK[a] - EXPOSURE_RANK[b])[0] || 'unknown';
  }, [blast]);
  const suggestion = useMemo(
    () => (issue ? suggestFactors({ text: `${issue.summary}\n${issue.description}`, exposureKind: bestExposure, reportedInterfaces: entry }) : null),
    [issue, bestExposure, entry],
  );
  const rated = isImpactRated(impacts);
  const discoveredAt = saved?.discoveredAt || issue?.created?.slice(0, 10);
  const result = useMemo(() => {
    if (!rated || !factors) return null;
    try {
      return assessRisk({ impacts, factors, discoveredAt });
    } catch (e) {
      return { error: e.message };
    }
  }, [rated, impacts, factors, discoveredAt]);

  const run = async (name, fn) => {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setBusy(null);
    }
  };
  const onSave = () => run('save', async () => {
    const value = await invoke('saveAssessment', { component, affectedVersions, impacts, factors, discoveredAt, reportedInterfaces: entry });
    setSaved(value.current);
  });
  const onPublish = () => run('publish', async () => {
    const page = await invoke('publishAudit');
    setSaved((s) => ({ ...s, confluencePage: page }));
  });

  if (loading) return <Spinner label="Loading assessment" />;

  const ecuRows = (blast?.ecus || []).map((e) => {
    const exp = e.exposure && EXPOSURE_LOZENGE[e.exposure.kind];
    return {
      key: `${e.ecuId}-${e.component}`,
      cells: [
        { key: 'ecu', content: e.ecuName },
        { key: 'ver', content: e.installedVersion },
        { key: 'aff', content: <Lozenge appearance={e.affected ? 'removed' : 'success'}>{e.affected ? 'Affected' : 'Not affected'}</Lozenge> },
        { key: 'reach', content: exp ? <Stack space="space.050"><Lozenge appearance={exp.appearance}>{exp.text}</Lozenge><Text size="small">{e.exposure.note}</Text></Stack> : '-' },
        { key: 'lines', content: e.vehicleLines.join(', ') },
      ],
    };
  });

  return (
    <Stack space="space.200">
      {error && <SectionMessage appearance="error"><Text>{error}</Text></SectionMessage>}
      {inventory?.source === 'demo' && (
        <SectionMessage appearance="information"><Text>Using the demo inventory (fictional OEM). A Jira admin can import your own on the R155 Desk admin page.</Text></SectionMessage>
      )}

      <Heading size="small">1. Affected component and entry point</Heading>
      <Inline space="space.200" alignBlock="end">
        <Box xcss={{ width: '34%' }}>
          <Label labelFor="component">Component</Label>
          <Select id="component" options={componentOptions} value={optionFor(componentOptions, component)} onChange={(o) => setComponent(o?.value || '')} />
        </Box>
        <Box xcss={{ width: '24%' }}>
          <Label labelFor="versions">Affected versions (e.g. &lt;3.0.8)</Label>
          <Textfield id="versions" value={affectedVersions} onChange={(e) => setAffectedVersions(e.target.value)} />
        </Box>
        <Box xcss={{ width: '36%' }}>
          <Label labelFor="entry">Entry interface named in the report</Label>
          <Select id="entry" isMulti options={interfaceOptions} value={interfaceOptions.filter((o) => entry.includes(o.value))} onChange={(opts) => setEntry((opts || []).map((o) => o.value))} />
        </Box>
      </Inline>

      {blast && (
        <Stack space="space.100">
          <Text>
            <Strong>{blast.affectedEcuCount} affected ECU(s)</Strong>, {blast.directlyExposedEcuCount} directly exposed ·{' '}
            <Strong>{blast.fleetExposure.toLocaleString('en-US')} vehicles</Strong> in the field · markets: {blast.markets.join(', ') || 'none'}
          </Text>
          <DynamicTable
            head={{ cells: ['ECU', 'Installed', 'Status', 'Reachability from entry point', 'Vehicle lines'].map((c) => ({ key: c, content: c })) }}
            rows={ecuRows}
            emptyView="This component is not in the inventory."
          />
        </Stack>
      )}

      <Heading size="small">2. Impact (ISO/SAE 21434 · S/F/O/P)</Heading>
      <Inline space="space.150" shouldWrap>
        {IMPACT_CATEGORIES.map((c) => (
          <Box key={c} xcss={{ width: '23%' }}>
            <Label labelFor={`impact-${c}`}>{IMPACT_TITLES[c]}</Label>
            <Select id={`impact-${c}`} placeholder="Not rated" options={impactOptions} value={optionFor(impactOptions, impacts[c])} onChange={(o) => setImpacts({ ...impacts, [c]: o?.value })} />
          </Box>
        ))}
      </Inline>

      <Inline space="space.100" alignBlock="center" spread="space-between">
        <Heading size="small">3. Attack potential (Annex G)</Heading>
        {suggestion && <Button appearance="subtle" onClick={() => setFactors(suggestion.factors)}>Apply suggested factors</Button>}
      </Inline>
      <Inline space="space.150" shouldWrap>
        {Object.keys(ATTACK_POTENTIAL_FACTORS).map((f) => {
          const options = Object.entries(FACTOR_LABELS[f]).map(([value, label]) => ({ value, label: `${label} (${ATTACK_POTENTIAL_FACTORS[f][value]})` }));
          const differs = suggestion && factors && suggestion.factors[f] !== factors[f];
          return (
            <Box key={f} xcss={{ width: '31%' }}>
              <Label labelFor={`factor-${f}`}>{FACTOR_TITLES[f]}</Label>
              <Select id={`factor-${f}`} options={options} value={optionFor(options, factors?.[f])} onChange={(o) => setFactors({ ...factors, [f]: o.value })} />
              {suggestion && (
                <Text size="small">
                  {differs ? `Suggested: ${FACTOR_LABELS[f][suggestion.factors[f]]}. ` : ''}
                  {suggestion.reasons[f]}
                </Text>
              )}
            </Box>
          );
        })}
      </Inline>

      <Heading size="small">4. Risk</Heading>
      {!rated && <SectionMessage appearance="warning"><Text>Not rated yet: choose at least one impact rating. An unrated report has no risk value.</Text></SectionMessage>}
      {result?.error && <SectionMessage appearance="warning"><Text>{result.error}</Text></SectionMessage>}
      {result && !result.error && (
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

      <Inline space="space.200" alignBlock="center" shouldWrap>
        <Button appearance="primary" onClick={onSave} isDisabled={!component || !result || !!result.error || !!busy}>
          {busy === 'save' ? 'Saving…' : 'Save assessment'}
        </Button>
        {confluenceSpaceKey && (
          <Button onClick={onPublish} isDisabled={!saved || !!busy}>
            {busy === 'publish' ? 'Publishing…' : saved?.confluencePage ? 'Update audit record' : 'Publish audit record'}
          </Button>
        )}
        {saved && <Text>Last saved {saved.savedAt.slice(0, 16).replace('T', ' ')} UTC</Text>}
        {saved?.confluencePage?.url && <Link href={saved.confluencePage.url} openNewTab>Audit record in Confluence</Link>}
      </Inline>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
