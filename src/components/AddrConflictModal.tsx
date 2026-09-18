import { useState } from 'react';
import { Plan } from '../lib/model';
import { longToIpv4, parseCidr } from '../lib/ip';
import {
  IpConflict,
  auditConflicts,
  describeAssignment,
  formatConflictReport,
  parseObservations,
} from '../lib/addrConflict';

interface Props {
  plan: Plan;
  onClose: () => void;
}

/**
 * 地址观测冲突审计弹窗：粘贴多行「ISO 时间, IPv4, MAC, 有效秒数」观测。
 * 先完整校验并规范化地址（任一行非法即带行号报错且不生成结果），
 * 再将每行视为半开有效区间 [start, start+ttl)，按 IP 扫描不同 MAC 的区间重叠。
 * 纯本地只读计算，不修改规划、不产生历史记录。
 */
export default function AddrConflictModal({ plan, onClose }: Props) {
  const allocations = plan.allocations
    .map((alloc) => ({ alloc, cidr: parseCidr(alloc.cidr)! }))
    .filter((x) => x.cidr);
  const reportPlan = { roots: plan.roots, allocations };

  const [text, setText] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [conflicts, setConflicts] = useState<IpConflict[] | null>(null);
  const [obsCount, setObsCount] = useState(0);
  const [copied, setCopied] = useState(false);

  const run = () => {
    const { observations, errors: errs } = parseObservations(text);
    setErrors(errs);
    setCopied(false);
    if (errs.length > 0) {
      // 非法行须阻止生成
      setConflicts(null);
      return;
    }
    setObsCount(observations.length);
    setConflicts(auditConflicts(observations));
  };

  const report = conflicts
    ? formatConflictReport(conflicts, obsCount, reportPlan)
    : '';
  const conflictIpCount = conflicts ? new Set(conflicts.map((c) => c.ip)).size : 0;

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(report);
    } catch {
      // 剪贴板 API 不可用（如非安全上下文）时回退
      const ta = document.createElement('textarea');
      ta.value = report;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <h3>地址观测冲突审计</h3>
        <p className="muted">
          每行粘贴一条观测：<code>ISO 时间, IPv4, MAC, 有效秒数</code>（空行跳过）。
          地址先完整校验并规范化（MAC 支持 <code>aa:bb:cc:dd:ee:ff</code>、
          <code>aa-bb-…</code>、<code>aabb.ccdd.eeff</code> 等写法）；每行构成半开有效区间
          <code>[起, 起+秒数)</code>，按 IP 扫描不同 MAC 的区间重叠，连续且参与方集合相同的冲突段自动合并。
          仅端点相接的历史换机<strong>不会</strong>误报。<strong>任一非法行带行号报错且不生成结果。</strong>
          纯本地只读计算，不修改规划与历史。
        </p>
        <label className="field">
          <span>观测记录（每行：ISO 时间, IPv4, MAC, 有效秒数）</span>
          <textarea
            autoFocus
            rows={8}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={
              '例如：\n2026-09-18T10:00:00Z, 192.168.0.10, aa:bb:cc:00:00:01, 300\n2026-09-18T10:02:00Z, 192.168.0.10, AA:BB:CC:00:00:02, 300'
            }
            spellCheck={false}
          />
        </label>
        {errors.length > 0 && (
          <ul className="errors">
            {errors.map((er, i) => (
              <li key={i}>{er}</li>
            ))}
          </ul>
        )}
        {conflicts && (
          <div className="dhcp-result">
            <div className="dhcp-result-head">
              <span>
                有效观测 {obsCount} 行 · 冲突 IPv4 {conflictIpCount} 个 · 冲突区间 {conflicts.length} 段
              </span>
              <button className="btn small" onClick={copyReport}>
                {copied ? '已复制 ✓' : '复制审计报告'}
              </button>
            </div>
            {conflicts.length === 0 ? (
              <p className="muted">
                未发现冲突：同 IP 的不同 MAC 观测区间互不重叠（历史换机已正确排除）。
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>IPv4</th>
                      <th>当前子网分配</th>
                      <th>冲突起（含）</th>
                      <th>冲突止（不含）</th>
                      <th>冲突参与 MAC</th>
                    </tr>
                  </thead>
                  <tbody>
                    {conflicts.map((c, i) => (
                      <tr key={i} className="conflict-row">
                        <td>
                          <code>{longToIpv4(c.ip)}</code>
                        </td>
                        <td>{describeAssignment(c.ip, reportPlan)}</td>
                        <td>
                          <code>{new Date(c.startMs).toISOString()}</code>
                        </td>
                        <td>
                          <code>{new Date(c.endMs).toISOString()}</code>
                        </td>
                        <td>
                          {c.macs.map((mac) => (
                            <span key={mac} className="badge conflict-mac">
                              {mac}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
        <div className="modal-actions">
          <button className="btn" onClick={onClose}>
            关闭
          </button>
          <button className="btn primary" onClick={run}>
            执行审计
          </button>
        </div>
      </div>
    </div>
  );
}
