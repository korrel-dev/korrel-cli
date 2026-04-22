#!/usr/bin/env node
import { Command } from 'commander';
import { runAudit } from './audit.js';

const program = new Command();

program
  .name('korrel')
  .description('Audit MCP servers for OAuth 2.1 and spec compliance.')
  .version('0.0.0');

program
  .command('audit')
  .description('Run an audit against an MCP server URL.')
  .argument('<url>', 'Base URL of the MCP server (e.g. https://mcp.example.com/)')
  .option('-o, --output <dir>', 'Output directory root', './audits')
  .action(async (url: string, options: { output: string }) => {
    try {
      await runAudit(url, options.output);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[korrel] error: ${message}`);
      process.exitCode = 1;
    }
  });

await program.parseAsync(process.argv);
