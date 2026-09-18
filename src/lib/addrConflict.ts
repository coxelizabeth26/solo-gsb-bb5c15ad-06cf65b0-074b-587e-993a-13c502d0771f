/**
 * 地址观测冲突审计：粘贴多行「ISO 时间, IPv4, MAC, 有效秒数」观测，
 * 先完整校验并规范化地址，再把每行视为一个半开有效区间 [start, start + ttl)；
 * 按 IP 扫描不同 MAC 的区间重叠，并合并连续的同一冲突参与方集合。
 *
 * 非重叠的历史换机（区间仅端点相接或完全分离）不会误报。
 * 纯本地只读计算：不修改规划、不产生修订与历史记录。
 */
import { Allocation, RootBlock } from './model';
import { Cidr, ipv4ToLong, lastAddr, longToIpv4, parseCidr } from './ip';

/** 规范化后的一条观测（物理行号从 1 开始） */
export interface Observation {
  lineNo: number;
  /** 观测起始时刻（epoch 毫秒，UTC） */
  startMs: number;
  /** 半开区间结束时刻 startMs + ttlSeconds * 1000 */
  endMs: number;
  /** uint32 IPv4 */
  ip: number;
  /** 规范化 MAC：小写冒号分隔，aa:bb:cc:dd:ee:ff */
  mac: string;
  ttlSeconds: number;
}

export interface ObservationParseResult {
  observations: Observation[];
  /** 逐行错误信息（带行号）；非空时不得执行审计、不生成结果 */
  errors: string[];
}

/** 合并后的一段冲突：同一组 MAC 在整个 [startMs, endMs) 内同时有效 */
export interface IpConflict {
  ip: number;
  startMs: number;
  endMs: number;
  /** 冲突参与 MAC（规范化、升序去重） */
  macs: string[];
}

export interface AssignmentInfo {
  alloc: Allocation;
  cidr: Cidr;
}

// ---- 地址规范化 ----

/**
 * 规范化 MAC：支持
 *  - 冒号/连字符分隔的 6 组两位十六进制（aa:bb:cc:dd:ee:ff、AA-BB-...）；
 *  - 点分隔的 3 组四位十六进制（aabb.ccdd.eeff）；
 *  - 无分隔的 12 位十六进制。
 * 统一输出小写冒号形式；非法返回 null。
 */
export function normalizeMac(input: string): string | null {
  const text = input.trim().toLowerCase();
  if (!text) return null;
  const pair = /^[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}$/;
  const cisco = /^[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}$/;
  const plain = /^[0-9a-f]{12}$/;
  if (!pair.test(text) && !cisco.test(text) && !plain.test(text)) return null;
  const hex = text.replace(/[^0-9a-f]/g, '');
  const groups: string[] = [];
  for (let i = 0; i < hex.length; i += 2) groups.push(hex.slice(i, i + 2));
  return groups.join(':');
}

/**
 * 严格解析 ISO 8601 日期时间：`YYYY-MM-DDTHH:mm:ss[.fraction][Z|±HH:mm]`，
 * 日期与时间之间允许空格。不带时区时按浏览器本地时区解释。
 * 对日历做真实校验（拒绝 2026-02-29 之类）。非法返回 null。
 */
export function parseIsoDateTime(input: string): number | null {
  const text = input.trim();
  const m = text.match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?(Z|[+-]\d{2}:\d{2})?$/,
  );
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (hour > 23 || minute > 59 || second > 59) return null;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]) return null;
  const fraction = m[7] ?? '';
  const millisecond = fraction ? Number((fraction + '000').slice(0, 3)) : 0;

  let epoch: number;
  const tz = m[8];
  if (tz === undefined) {
    // 不带时区：按浏览器本地时间解释
    epoch = new Date(year, month - 1, day, hour, minute, second, millisecond).getTime();
  } else {
    let offsetMs = 0;
    if (tz !== 'Z') {
      const om = tz.match(/^([+-])(\d{2}):(\d{2})$/);
      if (!om) return null;
      const offHour = Number(om[2]);
      const offMinute = Number(om[3]);
      if (offHour > 23 || offMinute > 59) return null;
      offsetMs = (offHour * 60 + offMinute) * 60_000 * (om[1] === '-' ? -1 : 1);
    }
    epoch = Date.UTC(year, month - 1, day, hour, minute, second, millisecond) - offsetMs;
  }
  if (!Number.isFinite(epoch) || Math.abs(epoch) > MAX_DATE_MS) return null;
  return epoch;
}

const MAX_DATE_MS = 8_640_000_000_000_000;

/** 解析有效秒数：不小于 1 的非负整数字面量（拒绝小数、正负号与越界值）。 */
export function parseTtlSeconds(input: string): number | null {
  const text = input.trim();
  if (!/^\d+$/.test(text)) return null;
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < 1) return null;
  return value;
}

// ---- 逐行解析 ----

/** 解析单行观测（不含行号前缀）。空行返回 null；非法时 error 为错误说明。 */
function parseObservationLine(
  lineNo: number,
  line: string,
): { observation: Observation } | { error: string } | null {
  const text = line.trim();
  if (!text) return null;
  const tokens = text.split(',').map((t) => t.trim());
  if (tokens.length !== 4) {
    return {
      error: `第 ${lineNo} 行：应为 4 个字段（ISO 时间, IPv4, MAC, 有效秒数），实际 ${tokens.length} 个（${text}）`,
    };
  }
  const [timeToken, ipToken, macToken, ttlToken] = tokens;

  if (!timeToken) return { error: `第 ${lineNo} 行：ISO 时间为空` };
  const startMs = parseIsoDateTime(timeToken);
  if (startMs === null) {
    return { error: `第 ${lineNo} 行：ISO 时间非法（应为 YYYY-MM-DDTHH:mm:ss，可选小数秒与时区）：${timeToken}` };
  }

  if (!ipToken) return { error: `第 ${lineNo} 行：IPv4 地址为空` };
  const ip = ipv4ToLong(ipToken);
  if (ip === null) {
    return { error: `第 ${lineNo} 行：IPv4 地址非法：${ipToken}` };
  }

  if (!macToken) return { error: `第 ${lineNo} 行：MAC 地址为空` };
  const mac = normalizeMac(macToken);
  if (mac === null) {
    return { error: `第 ${lineNo} 行：MAC 地址非法（支持 aa:bb:cc:dd:ee:ff / aa-bb-... / aabb.ccdd.eeff）：${macToken}` };
  }

  if (!ttlToken) return { error: `第 ${lineNo} 行：有效秒数为空` };
  const ttlSeconds = parseTtlSeconds(ttlToken);
  if (ttlSeconds === null) {
    return { error: `第 ${lineNo} 行：有效秒数必须为不小于 1 的整数：${ttlToken}` };
  }
  const endMs = startMs + ttlSeconds * 1000;
  if (!Number.isFinite(endMs) || Math.abs(endMs) > MAX_DATE_MS) {
    return { error: `第 ${lineNo} 行：有效区间结束时间超出可表示范围（${timeToken} + ${ttlSeconds}s）` };
  }

  return { observation: { lineNo, startMs, endMs, ip, mac, ttlSeconds } };
}

/**
 * 逐行解析观测文本：空行跳过；任一行非法即按行收集错误并阻止生成结果。
 * 所有地址在进入区间运算前已完整校验并规范化。
 */
export function parseObservations(text: string): ObservationParseResult {
  const observations: Observation[] = [];
  const errors: string[] = [];
  const stripped = text.replace(/^\uFEFF/, '');
  stripped
    .split('\n')
    .forEach((rawLine, i) => {
      const parsed = parseObservationLine(i + 1, rawLine);
      if (parsed === null) return;
      if ('error' in parsed) {
        errors.push(parsed.error);
        return;
      }
      observations.push(parsed.observation);
    });
  return { observations, errors };
}

// ---- 当前子网分配 ----

/** 查找 IP 当前所属的分配：取最长前缀（最具体）匹配，命名保留段同样参与。 */
export function lookupAssignment(
  ip: number,
  allocations: { alloc: Allocation; cidr: Cidr }[],
): AssignmentInfo | null {
  let best: AssignmentInfo | null = null;
  for (const item of allocations) {
    if (ip >= item.cidr.base && ip <= lastAddr(item.cidr)) {
      if (!best || item.cidr.prefix > best.cidr.prefix) best = item;
    }
  }
  return best;
}

/** 未分配时查找包含该 IP 的根网段（用于报告标注）。 */
export function lookupRoot(ip: number, roots: RootBlock[]): RootBlock | null {
  for (const root of roots) {
    const c = parseCidr(root.cidr);
    if (c && ip >= c.base && ip <= lastAddr(c)) return root;
  }
  return null;
}

// ---- 冲突扫描 ----

interface TimedEvent {
  t: number;
  /** 同一时刻先结束后开始，保证半开区间端点相接不误判 */
  kind: 'end' | 'start';
  mac: string;
}

/**
 * 扫描单个 IP 的观测区间，返回合并后的冲突段：
 * 用扫描线维护各 MAC 的有效计数（同一 MAC 重复观测以多重集计数），
 * 当同一时刻存在 ≥2 个不同 MAC 时记为冲突；相邻且参与方集合相同的冲突段合并。
 */
export function conflictsForIp(observations: Observation[]): IpConflict[] {
  if (observations.length === 0) return [];
  const events: TimedEvent[] = [];
  for (const o of observations) {
    events.push({ t: o.startMs, kind: 'start', mac: o.mac });
    events.push({ t: o.endMs, kind: 'end', mac: o.mac });
  }
  events.sort((a, b) => a.t - b.t || (a.kind === b.kind ? 0 : a.kind === 'end' ? -1 : 1));

  const counts = new Map<string, number>();
  const raws: { start: number; end: number; key: string; macs: string[] }[] = [];

  // 首组事件必为 start；处理后区间从该时刻开始
  let segStart = events[0].t;
  let i = 0;
  while (i < events.length) {
    const t = events[i].t;
    if (t > segStart) {
      // [segStart, t) 内有效的参与方集合 = 处理当前时刻事件之前的计数
      const macs = [...counts.keys()].filter((mac) => (counts.get(mac) ?? 0) > 0).sort();
      if (macs.length >= 2) {
        raws.push({ start: segStart, end: t, key: macs.join(','), macs });
      }
    }
    // 处理同一时刻的全部事件（end 先于 start，排序已保证）
    while (i < events.length && events[i].t === t) {
      const e = events[i];
      const cur = counts.get(e.mac) ?? 0;
      counts.set(e.mac, e.kind === 'start' ? cur + 1 : cur - 1);
      i++;
    }
    segStart = t;
  }

  // 合并连续（端点相接）且参与方集合相同的冲突段
  const merged: IpConflict[] = [];
  for (const seg of raws) {
    const last = merged[merged.length - 1];
    if (last && last.endMs === seg.start && last.macs.join(',') === seg.key) {
      last.endMs = seg.end;
    } else {
      merged.push({ ip: observations[0].ip, startMs: seg.start, endMs: seg.end, macs: seg.macs });
    }
  }
  return merged;
}

/**
 * 按 IP 分组扫描区间重叠。结果按 IPv4 数值升序、同 IP 按冲突起始升序。
 */
export function auditConflicts(observations: Observation[]): IpConflict[] {
  const byIp = new Map<number, Observation[]>();
  for (const o of observations) {
    const list = byIp.get(o.ip);
    if (list) list.push(o);
    else byIp.set(o.ip, [o]);
  }
  const out: IpConflict[] = [];
  for (const ip of [...byIp.keys()].sort((a, b) => a - b)) {
    out.push(...conflictsForIp(byIp.get(ip)!));
  }
  return out;
}

// ---- 文本报告 ----

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

function formatLocalTime(d: Date): string {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(
    d.getHours(),
  )}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

/** 描述 IP 当前所属子网分配（含命名保留段）；无匹配时标注根网段或越界。 */
export function describeAssignment(
  ip: number,
  plan: { roots: RootBlock[]; allocations: { alloc: Allocation; cidr: Cidr }[] },
): string {
  const hit = lookupAssignment(ip, plan.allocations);
  if (hit) return `${hit.alloc.name}  ${longToIpv4(hit.cidr.base)}/${hit.cidr.prefix}（${hit.alloc.kind}）`;
  const root = lookupRoot(ip, plan.roots);
  if (root) return `未分配（位于根网段「${root.name}」${root.cidr}）`;
  return '未分配（不在任何根网段内）';
}

/** 生成可复制的纯文本审计报告（顺序与结果表格一致）。 */
export function formatConflictReport(
  conflicts: IpConflict[],
  observationCount: number,
  plan: { roots: RootBlock[]; allocations: { alloc: Allocation; cidr: Cidr }[] },
  generatedAt = new Date(),
): string {
  const ipCount = new Set(conflicts.map((c) => c.ip)).size;
  const lines: string[] = [
    '地址观测冲突审计报告',
    `生成时间：${formatLocalTime(generatedAt)}`,
    `有效观测：${observationCount} 行 · 冲突 IPv4：${ipCount} 个 · 冲突区间：${conflicts.length} 段`,
    '区间均为半开 [起, 止)；非重叠的历史换机不计为冲突',
    '----------------------------------------',
  ];
  if (conflicts.length === 0) {
    lines.push('未发现冲突：同 IP 的不同 MAC 观测区间互不重叠。');
    return lines.join('\n');
  }
  let lastIp: number | null = null;
  for (const c of conflicts) {
    if (c.ip !== lastIp) {
      lines.push(`IP ${longToIpv4(c.ip)}`);
      lines.push(`  当前子网分配：${describeAssignment(c.ip, plan)}`);
      lastIp = c.ip;
    }
    const start = new Date(c.startMs).toISOString();
    const end = new Date(c.endMs).toISOString();
    lines.push(`  [${start}, ${end}) 参与方 ${c.macs.length}：${c.macs.join(', ')}`);
  }
  return lines.join('\n');
}
