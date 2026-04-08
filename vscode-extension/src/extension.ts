/**
 * Pact Sentinel VSCode Extension
 * Integrates the pact-sentinel CLI directly into VSCode
 * providing inline diagnostics, hover explanations, and a findings panel.
 */
import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

// ── Types ────────────────────────────────────────────
interface FindingLocation { module: string; function: string; line: number; }
interface Finding {
  id: string; rule_id: string; title: string; severity: string;
  location: FindingLocation; issue: string; risk: string;
  recommendation: string; fixed_code_example: string; confidence: number;
}
interface Report {
  findings: Finding[];
  risk_score: { security_score: number; letter_grade: string; label: string; };
  summary: string;
  error?: string;
}

// ── Severity → VSCode DiagnosticSeverity ─────────────
const SEV_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};

const SEV_EMOJI: Record<string, string> = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🟢'
};

// ── Extension activation ─────────────────────────────
export function activate(context: vscode.ExtensionContext) {
  console.log('Pact Sentinel activated');

  const diagnosticCollection = vscode.languages.createDiagnosticCollection('pact-sentinel');
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.command = 'pact-sentinel.showReport';
  context.subscriptions.push(diagnosticCollection, statusBar);

  // ── Commands ─────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand('pact-sentinel.analyzeFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || !editor.document.fileName.endsWith('.pact')) {
        vscode.window.showWarningMessage('Please open a .pact file first.');
        return;
      }
      await analyzeDocument(editor.document, diagnosticCollection, statusBar, context);
    }),

    vscode.commands.registerCommand('pact-sentinel.analyzeWorkspace', async () => {
      const files = await vscode.workspace.findFiles('**/*.pact', '**/node_modules/**');
      vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'Pact Sentinel: Scanning workspace…', cancellable: false },
        async (progress) => {
          let total = 0;
          for (const file of files) {
            const doc = await vscode.workspace.openTextDocument(file);
            await analyzeDocument(doc, diagnosticCollection, statusBar, context);
            total++;
            progress.report({ message: `${total}/${files.length} files`, increment: 100 / files.length });
          }
          vscode.window.showInformationMessage(`Pact Sentinel: Scanned ${total} file(s).`);
        }
      );
    }),

    vscode.commands.registerCommand('pact-sentinel.showReport', () => {
      const panel = vscode.window.createWebviewPanel(
        'pactSentinelReport', 'Pact Sentinel Report',
        vscode.ViewColumn.Beside, { enableScripts: true }
      );
      const lastReport = context.workspaceState.get<Report>('lastReport');
      panel.webview.html = buildReportHtml(lastReport);
    }),
  );

  // ── Auto-analyze on save ─────────────────────────
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const config = vscode.workspace.getConfiguration('pact-sentinel');
      if (config.get('analyzeOnSave') && doc.fileName.endsWith('.pact')) {
        await analyzeDocument(doc, diagnosticCollection, statusBar, context);
      }
    })
  );

  // ── Hover provider for inline explanation ────────
  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ language: 'pact' }, {
      provideHover(document, position) {
        const diagnostics = diagnosticCollection.get(document.uri) || [];
        const hovered = diagnostics.filter(d => d.range.contains(position));
        if (!hovered.length) return null;
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        for (const d of hovered) {
          md.appendMarkdown(`### ${d.message}\n`);
          if (d.source) md.appendMarkdown(`*${d.source}*\n\n`);
        }
        return new vscode.Hover(md);
      }
    })
  );

  statusBar.text = '$(shield) Pact Sentinel';
  statusBar.tooltip = 'Pact Sentinel: Click to view report';
  statusBar.show();
}

// ── Core analysis function ─────────────────────────────
async function analyzeDocument(
  document: vscode.TextDocument,
  diagnostics: vscode.DiagnosticCollection,
  statusBar: vscode.StatusBarItem,
  context: vscode.ExtensionContext,
): Promise<void> {
  const config = vscode.workspace.getConfiguration('pact-sentinel');
  const pythonPath = config.get<string>('pythonPath', 'python3');
  const sentinelPath = config.get<string>('sentinelPath') ||
    findSentinelPath(context);
  const apiKey = config.get<string>('geminiApiKey', '');
  const useAI = config.get<boolean>('enableAI', false);
  const severityThreshold = config.get<string>('severityThreshold', 'medium');
  const skipRules = config.get<string[]>('skipRules', []);

  if (!sentinelPath) {
    vscode.window.showErrorMessage('Pact Sentinel: cli.py not found. Set pact-sentinel.sentinelPath in settings.');
    return;
  }

  statusBar.text = '$(sync~spin) Pact Sentinel: Analyzing…';

  const args = [
    sentinelPath,
    document.fileName,
    '--format', 'json',
    '--no-color',
    '--confidence', '0.5',
  ];
  if (!useAI) args.push('--no-ai');
  if (skipRules.length) args.push('--skip-rules', skipRules.join(','));

  const env = { ...process.env };
  if (apiKey) env.GEMINI_API_KEY = apiKey;

  try {
    const output = await runCommand(pythonPath, args, env);
    const report: Report = JSON.parse(output);
    context.workspaceState.update('lastReport', report);

    const diagList: vscode.Diagnostic[] = [];
    const sevOrder: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
    const threshold = sevOrder[severityThreshold] ?? 1;

    for (const finding of report.findings || []) {
      if ((sevOrder[finding.severity] ?? 0) < threshold) continue;

      const line = Math.max(0, (finding.location?.line || 1) - 1);
      const lineText = document.lineAt(Math.min(line, document.lineCount - 1));
      const range = new vscode.Range(
        line, lineText.firstNonWhitespaceCharacterIndex,
        line, lineText.text.length
      );

      const diag = new vscode.Diagnostic(
        range,
        `${SEV_EMOJI[finding.severity]} [${finding.id}] ${finding.title}`,
        SEV_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning
      );
      diag.source = `pact-sentinel (${finding.rule_id})`;
      diag.code = { value: finding.rule_id, target: vscode.Uri.parse('https://github.com/your-org/pact-sentinel#rules') };
      diagList.push(diag);
    }

    diagnostics.set(document.uri, diagList);

    const rs = report.risk_score;
    const grade = rs?.letter_grade || '?';
    const score = rs?.security_score || 0;
    const gradeEmoji = score >= 80 ? '✅' : score >= 55 ? '⚠' : '🔴';
    statusBar.text = `${gradeEmoji} Pact: ${grade} (${diagList.length} findings)`;
    statusBar.tooltip = `Score: ${score.toFixed(1)}/100 — ${rs?.label || ''}\n${report.summary || ''}`;

  } catch (err: any) {
    statusBar.text = '$(error) Pact Sentinel: Error';
    vscode.window.showErrorMessage(`Pact Sentinel error: ${err.message}`);
  }
}

function runCommand(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = cp.spawn(cmd, args, { env });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d: Buffer) => stdout += d.toString());
    proc.stderr.on('data', (d: Buffer) => stderr += d.toString());
    proc.on('close', (code) => {
      if (code !== 0 && !stdout.startsWith('{')) {
        reject(new Error(stderr || `Exit code ${code}`));
      } else {
        resolve(stdout);
      }
    });
    proc.on('error', reject);
  });
}

function findSentinelPath(context: vscode.ExtensionContext): string {
  // Check common locations
  const candidates = [
    path.join(context.extensionPath, '..', 'cli.py'),
    path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', 'cli.py'),
    path.join(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', 'pact-sentinel', 'cli.py'),
  ];
  const fs = require('fs');
  return candidates.find(p => { try { return fs.existsSync(p); } catch { return false; } }) || '';
}

function buildReportHtml(report?: Report): string {
  if (!report) return '<html><body style="background:#060810;color:#e2e8f0;font-family:monospace;padding:24px"><h2>No report yet — open a .pact file and run Analyze.</h2></body></html>';
  const rs = report.risk_score;
  const findings = report.findings || [];
  const rows = findings.map(f =>
    `<tr>
      <td>${SEV_EMOJI[f.severity] || ''} ${f.id}</td>
      <td>${f.title}</td>
      <td>${f.severity}</td>
      <td>${f.location?.function || '?'} : ${f.location?.line || '?'}</td>
    </tr>`
  ).join('');
  return `<!DOCTYPE html><html><head><style>
    body { background:#060810;color:#e2e8f0;font-family:monospace;padding:24px; }
    h1 { color:#3b82f6; } table { width:100%;border-collapse:collapse; }
    th { text-align:left;padding:8px;border-bottom:1px solid #1e2531;color:#94a3b8; }
    td { padding:8px;border-bottom:1px solid #0d1117;font-size:12px; }
    .grade { font-size:48px;font-weight:900;color:${rs?.security_score >= 70 ? '#10b981' : rs?.security_score >= 40 ? '#eab308' : '#ef4444'}; }
  </style></head><body>
    <h1>🛡️ Pact Sentinel Report</h1>
    <div class="grade">${rs?.letter_grade || '?'}</div>
    <p>Score: ${rs?.security_score?.toFixed(1) || '?'}/100 — ${rs?.label || ''}</p>
    <p>${report.summary || ''}</p>
    <h2>Findings (${findings.length})</h2>
    <table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Location</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </body></html>`;
}

export function deactivate() {}
