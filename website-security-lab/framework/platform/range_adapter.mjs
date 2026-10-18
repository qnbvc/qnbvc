#!/usr/bin/env node
/**
 * 把平台 ⑧ 导出的 report_*.json 转成靶场 scorer.mjs 能直接吃的格式。
 *
 * 为什么需要这一层：scorer.mjs 的分级一致性用的是中文等级（严重/高/中/低），
 * 而我们 findings 里带的是 severity(英文) 与 level(P0~P3)。--map 只能改字段名、改不了值，
 * 所以要在中间做一次值转换，否则"分级一致性"这一栏永远是空的。
 *
 * 用法：
 *   node range_adapter.mjs --findings report_20261016-003823.json --out scorer-input.json
 *   node scorer.mjs --findings scorer-input.json --out report.md --json metrics.json
 *
 * 说明：status=suppressed 的条目（被白名单抑制的误报）默认不输出，
 *      它们本来就不该参与召回率计算；加 --keep-suppressed 可以保留。
 */

import fs from 'node:fs';
import path from 'node:path';

const LEVEL_BY_P = { P0: '严重', P1: '高', P2: '中', P3: '低' };
const LEVEL_BY_SEVERITY = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };

function toChineseLevel(finding) {
  const level = String(finding.level ?? '').toUpperCase();
  if (LEVEL_BY_P[level]) return LEVEL_BY_P[level];
  const severity = String(finding.severity ?? '').toLowerCase();
  return LEVEL_BY_SEVERITY[severity] ?? '信息';
}

function toEvidenceText(evidence) {
  if (Array.isArray(evidence)) return evidence.filter(Boolean).join('；');
  return String(evidence ?? '');
}

function parseArgs(argv) {
  const read = (name, fallback) => {
    const index = argv.indexOf(name);
    return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
  };
  return {
    findings: read('--findings', ''),
    out: read('--out', 'scorer-input.json'),
    keepSuppressed: argv.includes('--keep-suppressed'),
  };
}

function main() {
  const { findings: inputPath, out, keepSuppressed } = parseArgs(process.argv.slice(2));
  if (!inputPath) {
    console.error('用法：node range_adapter.mjs --findings <⑧导出的json> [--out scorer-input.json]');
    process.exit(2);
  }

  const raw = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  const list = Array.isArray(raw)
    ? raw
    : (raw.findings ?? raw.results ?? raw.data ?? []);
  if (!Array.isArray(list)) {
    console.error('输入里找不到 findings / results / data 数组');
    process.exit(2);
  }

  const suppressedCount = list.filter((item) => String(item.status ?? '') === 'suppressed').length;
  const picked = keepSuppressed
    ? list
    : list.filter((item) => String(item.status ?? '') !== 'suppressed');

  const converted = picked.map((item, index) => {
    const urls = Array.isArray(item.affected_urls) ? item.affected_urls : [];
    return {
      id: item.id ?? `F-${String(index + 1).padStart(3, '0')}`,
      url: item.url || urls[0] || '',
      title: item.title ?? '',
      type: item.type ?? '',
      rule_id: item.rule_id ?? '',
      // scorer.mjs 用这个字段做分级一致性比对，必须是中文等级
      level: toChineseLevel(item),
      severity_original: item.severity ?? '',
      evidence: toEvidenceText(item.evidence),
      cwe: item.cwe ?? '',
      status: item.status ?? '',
      tool: item.tool ?? '',
      risk_score: item.risk_score ?? '',
      source_line: item.source_line ?? '',
    };
  });

  const missingUrl = converted.filter((item) => !item.url).length;
  fs.writeFileSync(out, JSON.stringify({ findings: converted }, null, 2), 'utf8');

  const byLevel = {};
  for (const item of converted) byLevel[item.level] = (byLevel[item.level] ?? 0) + 1;
  console.log(`已转换 ${converted.length} 条 → ${path.resolve(out)}`);
  console.log(`  等级分布：${JSON.stringify(byLevel)}`);
  if (suppressedCount) {
    console.log(`  另有 ${suppressedCount} 条被白名单抑制，已排除（--keep-suppressed 可保留）`);
  }
  if (missingUrl) {
    console.log(`  ⚠ ${missingUrl} 条没有 url，评分时匹配不上：检查 ⑤/⑥ 是否给出具体路径`);
  }
  console.log('\n下一步：node scorer.mjs --findings ' + path.basename(out) + ' --out report.md --json metrics.json');
}

main();
