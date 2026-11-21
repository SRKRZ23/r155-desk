/**
 * R155 Desk admin page (Jira settings > Apps). UI Kit.
 *
 *  - Inventory: paste a CSV (one row per vehicle line x ECU x component) or JSON export, preview the result
 *    and the validation problems, then save it. "Reset to demo" goes back to the fictional demo OEM.
 *  - Settings: automatic first-look note on new tickets, project filter, Confluence space for audit records.
 *
 * Every write is re-checked on the server (Jira admin permission), the page itself is only a convenience.
 */
import React, { useEffect, useState } from 'react';
import ForgeReconciler, {
  Button, CodeBlock, Heading, Inline, Label, List, ListItem, SectionMessage, Spinner, Stack, Text, TextArea, Textfield, Toggle,
} from '@forge/react';
import { invoke } from '@forge/bridge';

const Summary = ({ s }) => (
  <Text>
    {s.oem} ({s.source}{s.importedAt ? `, imported ${s.importedAt.slice(0, 16).replace('T', ' ')} UTC` : ''}): {s.vehicleLines} vehicle line(s),{' '}
    {s.ecus} ECU(s), {s.components} component entries, {Number(s.fleet).toLocaleString('en-US')} vehicles.
  </Text>
);

const App = () => {
  const [data, setData] = useState(null);
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);
  const [settings, setSettings] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = () => invoke('loadAdmin').then((d) => {
    setData(d);
    setSettings({ ...d.settings, projectKeys: d.settings.projectKeys.join(', ') });
  });
  useEffect(() => { load().catch((e) => setMessage({ type: 'error', text: e.message })); }, []);

  const run = async (fn) => {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
    } catch (e) {
      setMessage({ type: 'error', text: e.message || String(e) });
    } finally {
      setBusy(false);
    }
  };

  if (!data || !settings) return <Spinner label="Loading R155 Desk settings" />;

  return (
    <Stack space="space.300">
      {message && <SectionMessage appearance={message.type}><Text>{message.text}</Text></SectionMessage>}

      <Stack space="space.150">
        <Heading size="medium">Vehicle and ECU inventory</Heading>
        <Summary s={data.summary} />
        <Text>
          Paste a CSV with the columns below (one row per vehicle line, ECU and software component; lists separated by ";"),
          or a JSON export with "vehicleLines" and "ecus". "connects_to" describes the in-vehicle network and is used to
          tell directly exposed ECUs from ECUs reachable only through others.
        </Text>
        <CodeBlock language="text" text={data.csvTemplate.split('\n').slice(0, 4).join('\n')} />
        <Label labelFor="inventory">Inventory (CSV or JSON)</Label>
        <TextArea id="inventory" value={text} onChange={(e) => { setText(e.target.value); setPreview(null); }} placeholder="Paste CSV or JSON here" />
        <Inline space="space.100">
          <Button isDisabled={!text || busy} onClick={() => run(async () => setPreview(await invoke('previewImport', { text })))}>Preview</Button>
          <Button appearance="primary" isDisabled={!preview?.summary || busy} onClick={() => run(async () => {
            const r = await invoke('saveImport', { text });
            if (r.problems.length) setPreview(r);
            else { setMessage({ type: 'success', text: 'Inventory saved. New assessments use it immediately.' }); setText(''); setPreview(null); await load(); }
          })}>Save inventory</Button>
          <Button appearance="subtle" isDisabled={busy} onClick={() => setText(data.csvTemplate)}>Load template (demo data)</Button>
          <Button appearance="subtle" isDisabled={busy || data.summary.source === 'demo'} onClick={() => run(async () => {
            await invoke('resetInventory');
            setMessage({ type: 'success', text: 'Back to the demo inventory.' });
            await load();
          })}>Reset to demo</Button>
        </Inline>
        {preview?.summary && <SectionMessage appearance="success"><Summary s={preview.summary} /></SectionMessage>}
        {preview?.problems?.length > 0 && (
          <SectionMessage appearance="error">
            <List type="unordered">{preview.problems.map((p) => <ListItem key={p}>{p}</ListItem>)}</List>
          </SectionMessage>
        )}
      </Stack>

      <Stack space="space.150">
        <Heading size="medium">Settings</Heading>
        <Inline space="space.100" alignBlock="center">
          <Toggle id="auto" isChecked={settings.autoComment} onChange={() => setSettings({ ...settings, autoComment: !settings.autoComment })} />
          <Label labelFor="auto">Post an internal first-look note when a new ticket names a component from the inventory</Label>
        </Inline>
        <Label labelFor="projects">Only these projects (keys, comma separated; empty = all)</Label>
        <Textfield id="projects" value={settings.projectKeys} onChange={(e) => setSettings({ ...settings, projectKeys: e.target.value })} placeholder="SECOPS, PSIRT" />
        <Label labelFor="space">Confluence space key for audit records (empty = off)</Label>
        <Textfield id="space" value={settings.confluenceSpaceKey} onChange={(e) => setSettings({ ...settings, confluenceSpaceKey: e.target.value })} placeholder="SEC" />
        <Inline>
          <Button appearance="primary" isDisabled={busy} onClick={() => run(async () => {
            const s = await invoke('saveSettings', settings);
            setSettings({ ...s, projectKeys: s.projectKeys.join(', ') });
            setMessage({ type: 'success', text: 'Settings saved.' });
          })}>Save settings</Button>
        </Inline>
      </Stack>
    </Stack>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
