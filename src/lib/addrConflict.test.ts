import { describe, expect, it } from 'vitest';
import { Allocation, Plan } from './model';
import { ipv4ToLong, parseCidr } from './ip';
import {
  auditConflicts,
  conflictsForIp,
  describeAssignment,
  formatConflictReport,
  lookupAssignment,
  normalizeMac,
  parseIsoDateTime,
  parseObservations,
  parseTtlSeconds,
} from './addrConflict';
const T = (s: string) => Date.parse(s);

const obs = (
  lineNo: number,
  start: string,
  ip: string,
  mac: string,
  ttl: number,
) => ({
  observation: {
    lineNo,
    startMs: T(start),
    endMs: T(start) + ttl * 1000,
    ip: ipv4ToLong(ip)!,
    mac: normalizeMac(mac)!,
    ttlSeconds: ttl,
  },
});

describe('MAC 规范化', () => {
  it('接受冒号/连字符/点分/无分隔写法并统一为小写冒号形式', () => {
    expect(normalizeMac('aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeMac('AA:BB:CC:DD:EE:FF')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeMac('AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeMac('aabb.ccdd.eeff')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeMac('AABBCCDDEEFF')).toBe('aa:bb:cc:dd:ee:ff');
    expect(normalizeMac('  00:11:22:33:44:55  ')).toBe('00:11:22:33:44:55');
  });

  it('拒绝长度不对、分隔混用与非十六进制字符', () => {
    expect(normalizeMac('aa:bb:cc:dd:ee')).toBeNull();
    expect(normalizeMac('aa:bb:cc:dd:ee:ff:00')).toBeNull();
    expect(normalizeMac('aa-bb:cc-dd:ee-ff')).toBeNull();
    expect(normalizeMac('aabb.ccdd.ee')).toBeNull();
    expect(normalizeMac('zz:bb:cc:dd:ee:ff')).toBeNull();
    expect(normalizeMac('aa:bb:cc:dd:ee:gg')).toBeNull();
    expect(normalizeMac('')).toBeNull();
  });
});

describe('ISO 时间与 TTL 解析', () => {
  it('解析 UTC、带偏移与小数秒', () => {
    expect(parseIsoDateTime('2026-09-18T10:00:00Z')).toBe(Date.UTC(2026, 8, 18, 10, 0, 0));
    expect(parseIsoDateTime('2026-09-18T18:00:00+08:00')).toBe(Date.UTC(2026, 8, 18, 10, 0, 0));
    expect(parseIsoDateTime('2026-09-18T11:30:00-01:30')).toBe(Date.UTC(2026, 8, 18, 13, 0, 0));
    expect(parseIsoDateTime('2026-09-18 10:00:00Z')).toBe(Date.UTC(2026, 8, 18, 10, 0, 0));
    expect(parseIsoDateTime('2026-09-18T10:00:00.500Z')).toBe(Date.UTC(2026, 8, 18, 10, 0, 0, 500));
  });

  it('对日历做真实校验', () => {
    expect(parseIsoDateTime('2026-02-29T00:00:00Z')).toBeNull(); // 2026 非闰年
    expect(parseIsoDateTime('2024-02-29T00:00:00Z')).not.toBeNull(); // 2024 闰年
    expect(parseIsoDateTime('2026-13-01T00:00:00Z')).toBeNull();
    expect(parseIsoDateTime('2026-09-31T00:00:00Z')).toBeNull();
    expect(parseIsoDateTime('2026-09-18T24:00:00Z')).toBeNull();
    expect(parseIsoDateTime('2026-09-18T10:60:00Z')).toBeNull();
    expect(parseIsoDateTime('2026/09/18 10:00:00')).toBeNull();
    expect(parseIsoDateTime('not-a-time')).toBeNull();
  });

  it('TTL 仅接受 ≥1 的整数字面量', () => {
    expect(parseTtlSeconds('300')).toBe(300);
    expect(parseTtlSeconds(' 1 ')).toBe(1);
    expect(parseTtlSeconds('0')).toBeNull();
    expect(parseTtlSeconds('-5')).toBeNull();
    expect(parseTtlSeconds('1.5')).toBeNull();
    expect(parseTtlSeconds('abc')).toBeNull();
  });
});

describe('逐行解析', () => {
  it('合法行规范化地址与区间，空行跳过且保留物理行号', () => {
    const text = [
      '',
      '2026-09-18T10:00:00Z, 192.168.0.10, AA:BB:CC:00:00:01, 300',
      '   ',
      '2026-09-18 10:05:00Z,10.0.0.1,aabb.ccdd.eeff,1',
    ].join('\n');
    const { observations, errors } = parseObservations(text);
    expect(errors).toEqual([]);
    expect(observations.map((o) => o.lineNo)).toEqual([2, 4]);
    expect(observations[0]).toMatchObject({
      lineNo: 2,
      mac: 'aa:bb:cc:00:00:01',
      ttlSeconds: 300,
    });
    expect(observations[0].endMs - observations[0].startMs).toBe(300_000);
    expect(observations[1].mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('各类非法行带行号报错', () => {
    const text = [
      '2026-09-18T10:00:00Z, 192.168.0.10', // 字段不足
      '2026-09-18T10:00:00Z, 192.168.0.999, aa:bb:cc:00:00:01, 300', // IP 非法
      '2026-09-18T10:00:00Z, 192.168.0.10, zz:bb:cc:00:00:01, 300', // MAC 非法
      'not-a-time, 192.168.0.10, aa:bb:cc:00:00:01, 300', // 时间非法
      '2026-09-18T10:00:00Z, 192.168.0.10, aa:bb:cc:00:00:01, 0', // TTL 非法
      '2026-09-18T10:00:00Z, 192.168.0.10, aa:bb:cc:00:00:01, 300, extra', // 字段过多
    ].join('\n');
    const { observations, errors } = parseObservations(text);
    expect(observations).toEqual([]);
    expect(errors).toHaveLength(6);
    expect(errors[0]).toContain('第 1 行');
    expect(errors[1]).toContain('第 2 行');
    expect(errors[2]).toContain('第 3 行');
    expect(errors[3]).toContain('第 4 行');
    expect(errors[4]).toContain('第 5 行');
    expect(errors[5]).toContain('第 6 行');
    expect(errors[1]).toContain('IPv4 地址非法');
    expect(errors[2]).toContain('MAC 地址非法');
  });

  it('空文本合法（无观测、无冲突）', () => {
    const r = parseObservations('\n  \n');
    expect(r.errors).toEqual([]);
    expect(r.observations).toEqual([]);
  });
});

describe('半开区间冲突扫描', () => {
  const make = (rows: [string, string, string, number][]) =>
    rows.map((r, i) => obs(i + 1, r[0], r[1], r[2], r[3]).observation);

  it('非重叠的历史换机（端点相接）不误报', () => {
    // A 有效 [10:00, 10:05)，B 从 10:05 开始：仅端点相接
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 300],
      ['2026-09-18T10:05:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 300],
    ]);
    expect(conflictsForIp(rows)).toEqual([]);
  });

  it('完全分离的区间不误报', () => {
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 60],
      ['2026-09-18T11:00:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 60],
    ]);
    expect(conflictsForIp(rows)).toEqual([]);
  });

  it('重叠 1 秒即检出，且半开端点不进入冲突段', () => {
    // A [10:00:00, 10:05:00)，B [10:04:59, 10:05:59)：重叠 [10:04:59, 10:05:00)
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 300],
      ['2026-09-18T10:04:59Z', '192.168.0.10', 'aa:00:00:00:00:02', 60],
    ]);
    const conflicts = conflictsForIp(rows);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].startMs).toBe(T('2026-09-18T10:04:59Z'));
    expect(conflicts[0].endMs).toBe(T('2026-09-18T10:05:00Z'));
    expect(conflicts[0].macs).toEqual(['aa:00:00:00:00:01', 'aa:00:00:00:00:02']);
  });

  it('同一 MAC 的重复观测不构成冲突', () => {
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 300],
      ['2026-09-18T10:01:00Z', '192.168.0.10', 'AA:00:00:00:00:01', 300],
    ]);
    expect(conflictsForIp(rows)).toEqual([]);
  });

  it('合并连续的同一冲突参与方集合，参与方变化时分段', () => {
    // A [10:00, 10:10)；B [10:02, 10:04) 与 [10:06, 10:08)；C [10:03, 10:07)
    // [10:02,10:03) {A,B}；[10:03,10:04) {A,B,C}；[10:04,10:06) {A,C}；
    // [10:06,10:07) {A,B,C}；[10:07,10:08) {A,B}
    // {A,B} 两段不连续（中间参与方不同），不得合并
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 600],
      ['2026-09-18T10:02:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 120],
      ['2026-09-18T10:03:00Z', '192.168.0.10', 'aa:00:00:00:00:03', 240],
      ['2026-09-18T10:06:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 120],
    ]);
    const conflicts = conflictsForIp(rows);
    expect(conflicts.map((c) => [new Date(c.startMs).toISOString(), new Date(c.endMs).toISOString(), c.macs])).toEqual([
      ['2026-09-18T10:02:00.000Z', '2026-09-18T10:03:00.000Z', ['aa:00:00:00:00:01', 'aa:00:00:00:00:02']],
      [
        '2026-09-18T10:03:00.000Z',
        '2026-09-18T10:04:00.000Z',
        ['aa:00:00:00:00:01', 'aa:00:00:00:00:02', 'aa:00:00:00:00:03'],
      ],
      ['2026-09-18T10:04:00.000Z', '2026-09-18T10:06:00.000Z', ['aa:00:00:00:00:01', 'aa:00:00:00:00:03']],
      [
        '2026-09-18T10:06:00.000Z',
        '2026-09-18T10:07:00.000Z',
        ['aa:00:00:00:00:01', 'aa:00:00:00:00:02', 'aa:00:00:00:00:03'],
      ],
      ['2026-09-18T10:07:00.000Z', '2026-09-18T10:08:00.000Z', ['aa:00:00:00:00:01', 'aa:00:00:00:00:02']],
    ]);
  });

  it('参与方集合相同且端点相接的相邻冲突段合并为一段', () => {
    // A [10:00,10:10)；B [10:02,10:04)；B 又 [10:04,10:06)（与前段端点相接）
    // {A,B} 冲突 [10:02,10:06) 合并为一段
    const rows = make([
      ['2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 600],
      ['2026-09-18T10:02:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 120],
      ['2026-09-18T10:04:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 120],
    ]);
    const conflicts = conflictsForIp(rows);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].startMs).toBe(T('2026-09-18T10:02:00Z'));
    expect(conflicts[0].endMs).toBe(T('2026-09-18T10:06:00Z'));
  });

  it('按 IP 分组：不同 IP 的区间互不影响，结果按 IPv4 升序', () => {
    const rows = make([
      ['2026-09-18T10:00:00Z', '10.0.0.9', 'aa:00:00:00:00:01', 300],
      ['2026-09-18T10:00:00Z', '10.0.0.9', 'aa:00:00:00:00:02', 300],
      ['2026-09-18T10:00:00Z', '10.0.0.10', 'aa:00:00:00:00:01', 300],
      ['2026-09-18T10:00:00Z', '10.0.0.10', 'aa:00:00:00:00:03', 300],
    ]);
    const conflicts = auditConflicts(rows);
    expect(conflicts.map((c) => c.ip)).toEqual([
      ...rows.slice(0, 1).map((r) => r.ip),
      ...rows.slice(2, 3).map((r) => r.ip),
    ]);
    expect(conflicts[0].macs).toEqual(['aa:00:00:00:00:01', 'aa:00:00:00:00:02']);
    expect(conflicts[1].macs).toEqual(['aa:00:00:00:00:01', 'aa:00:00:00:00:03']);
  });
});

describe('当前子网分配', () => {
  const alloc = (name: string, cidr: string, kind: Allocation['kind'] = 'subnet'): Allocation => ({
    id: name,
    name,
    kind,
    prefix: parseCidr(cidr)!.prefix,
    cidr,
  });
  const plan: Plan = {
    version: 1,
    roots: [
      { id: 'r1', name: '办公网', cidr: '192.168.0.0/16' },
      { id: 'r2', name: '骨干', cidr: '10.0.0.0/8' },
    ],
    allocations: [
      alloc('办公有线', '192.168.0.0/24'),
      alloc('保留段', '192.168.0.0/28', 'reserved'),
      alloc('数据中心', '10.1.0.0/16'),
    ],
  };
  const items = plan.allocations.map((a) => ({ alloc: a, cidr: parseCidr(a.cidr)! }));
  const reportPlan = { roots: plan.roots, allocations: items };

  it('取最长前缀匹配（保留段优先于包含它的子网）', () => {
    const hit = lookupAssignment(0xc0a80005, items);
    expect(hit?.alloc.name).toBe('保留段');
    const hit2 = lookupAssignment(0xc0a800ff, items);
    expect(hit2?.alloc.name).toBe('办公有线');
    // 192.168.2.0 不在任何分配内
    expect(lookupAssignment(0xc0a80200, items)).toBeNull();
  });

  it('describeAssignment 输出子网 / 未分配根网段 / 越界三种描述', () => {
    // 10.1.2.3 ∈ 10.1.0.0/16
    expect(describeAssignment(0x0a010203, reportPlan)).toContain('数据中心  10.1.0.0/16');
    expect(describeAssignment(0xc0a80101, reportPlan)).toContain('未分配（位于根网段「办公网」192.168.0.0/16）');
    expect(describeAssignment(0x08080808, reportPlan)).toContain('不在任何根网段内');
  });
});

describe('文本报告', () => {
  it('列出每段冲突的起讫、MAC 与所属子网分配，无冲突时明确说明', () => {
    const plan: Plan = {
      version: 1,
      roots: [{ id: 'r1', name: '办公网', cidr: '192.168.0.0/16' }],
      allocations: [
        {
          id: 'a1',
          name: '办公有线',
          kind: 'subnet',
          prefix: 24,
          cidr: '192.168.0.0/24',
        },
      ],
    };
    const rows = [
      obs(1, '2026-09-18T10:00:00Z', '192.168.0.10', 'aa:00:00:00:00:01', 300).observation,
      obs(2, '2026-09-18T10:04:00Z', '192.168.0.10', 'aa:00:00:00:00:02', 300).observation,
    ];
    const conflicts = auditConflicts(rows);
    const report = formatConflictReport(
      conflicts,
      rows.length,
      { roots: plan.roots, allocations: plan.allocations.map((a) => ({ alloc: a, cidr: parseCidr(a.cidr)! })) },
      new Date('2026-09-18T12:00:00Z'),
    );
    expect(report).toContain('地址观测冲突审计报告');
    expect(report).toContain('有效观测：2 行 · 冲突 IPv4：1 个 · 冲突区间：1 段');
    expect(report).toContain('IP 192.168.0.10');
    expect(report).toContain('当前子网分配：办公有线  192.168.0.0/24');
    expect(report).toContain('[2026-09-18T10:04:00.000Z, 2026-09-18T10:05:00.000Z)');
    expect(report).toContain('aa:00:00:00:00:01, aa:00:00:00:00:02');

    const empty = formatConflictReport(
      [],
      1,
      { roots: plan.roots, allocations: [] },
      new Date('2026-09-18T12:00:00Z'),
    );
    expect(empty).toContain('冲突区间：0 段');
    expect(empty).toContain('未发现冲突');
  });
});
