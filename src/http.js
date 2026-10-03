/*
 * 限定版 HTTP/1.1 报文识别。
 *
 * 取证原则（对应需求）：
 *   - 只在【单方向、同一会话】内、连续且无冲突的已覆盖字节上识别报文；
 *     每个覆盖 run（两侧缺口之间的连续字节段）独立扫描，绝不把缺口两侧
 *     的文本拼成“看起来完整”的请求/响应；
 *   - 报文必须具备：合法起始行（request-line / status-line，HTTP/1.1）、
 *     逐条以 CRLF 结束的合法头部、以及空行结束的头部块；
 *   - 只支持【明确的 Content-Length】定长消息体（无 CL 也无 TE 时按空体处理）；
 *     分块传输编码（Transfer-Encoding: chunked）等一切 TE 一律标记“不支持”，
 *     不猜测正文边界、不向后扫描后续报文；
 *   - 候选若在当前 run 内被截断（起始线/头部/消息体不完整）、CL 非法或
 *     CL 声称长度超出连续覆盖区 => 一律标为“未完成”，不得输出伪完整报文；
 *   - 即使语法完整，只要报文区间内存在字节冲突位置，也标为“未完成”
 *     （该区间的字节事实不唯一，取证上不能称为确定的报文）；
 *   - 每条报文给出它在该方向流中的展开字节区间 [start,end)、相对序号区间，
 *     以及逐字节归属包号合并出的证据段；重传（相同字节的重叠到达）作为
 *     旁证包号列出；
 *   - run 起始处若有不属于任何合法起始线的前缀，只做一次起始线再同步，
 *     跳过字节数显式留痕（notice）；遇到无法识别的起始线立即停止该 run 的
 *     扫描，剩余字节以“未解析尾部”留痕，绝不猜边界。
 *
 * 输入是 reassemble 已 finalize 的单方向模型（runs 带 owners、conflicts、
 * retransEvents 已按展开位置排序），可被 Worker 与 Node 测试同时加载。
 */
(function (global, factory) {
  const api = factory();
  global.HttpLib = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const CR = 0x0d;
  const LF = 0x0a;
  const SP = 0x20;
  const HT = 0x09;
  const HTTP11 = 'HTTP/1.1';
  // 限定版只识别标准方法集合，降低在二进制正文里误命中起始线的概率。
  const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'];
  const MAX_HEADERS = 256;

  const decoder = new TextDecoder('utf-8');

  function decodeAscii(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  function isVChar(b) {
    return b >= 0x21 && b <= 0x7e;
  }
  function isUpperAlpha(b) {
    return b >= 0x41 && b <= 0x5a;
  }
  // RFC 7230 token = 1*tchar
  function isTokenChar(b) {
    if (b >= 0x61 && b <= 0x7a) return true; // a-z
    if (b >= 0x41 && b <= 0x5a) return true; // A-Z
    if (b >= 0x30 && b <= 0x39) return true; // 0-9
    return '!#$%&\'*+-.^_`|~'.indexOf(String.fromCharCode(b)) !== -1;
  }

  /**
   * 起始线“完整合法性”。line 不含结尾 CRLF。
   * 返回 {kind, ...} 或 null。
   */
  function validStartLine(line) {
    for (let i = 0; i < line.length; i++) {
      if (line[i] < SP || line[i] > 0x7e) return null; // 仅接受可见 ASCII
    }
    const s = decodeAscii(line);

    // ---- request-line = method SP request-target SP HTTP/1.1 ----
    const firstSp = s.indexOf(' ');
    if (firstSp > 0) {
      const method = s.slice(0, firstSp);
      if (METHODS.indexOf(method) !== -1) {
        const lastSp = s.lastIndexOf(' ');
        if (lastSp > firstSp + 1 && s.slice(lastSp + 1) === HTTP11) {
          const target = s.slice(firstSp + 1, lastSp);
          // request-target：单空格分隔已由 indexOf 保证，target 内不得再有空格；
          // '*'（OPTIONS）与 origin-form/absolute-form/authority-form 都属可见字符。
          if (target.indexOf(' ') === -1) {
            return { kind: 'request', method, target, version: HTTP11, text: s };
          }
        }
      }
    }

    // ---- status-line = HTTP/1.1 SP 3DIGIT SP reason-phrase ----
    if (s.slice(0, 8) === HTTP11 && s[8] === ' ') {
      const codeStr = s.slice(9, 12);
      if (/^[0-9]{3}$/.test(codeStr) && s.length >= 13 && s[12] === ' ') {
        let reasonOk = true;
        for (let i = 13; i < s.length; i++) {
          const c = s.charCodeAt(i);
          if (c !== HT && (c < SP || c > 0x7e)) { reasonOk = false; break; }
        }
        if (reasonOk) {
          return {
            kind: 'response',
            version: HTTP11,
            statusCode: parseInt(codeStr, 10),
            reason: s.slice(13),
            text: s
          };
        }
      }
    }
    return null;
  }

  /**
   * 可见字节 v（当前 run 内起始线位置到 run 末尾，尚未遇到 CRLF）是否可能是
   * 某条合法起始线的“前缀”。仅在 run 边界截断时使用：决定标“未完成起始线”
   * 而非“无法识别”。两种形态分别按字符推演，任何一步确定偏离即返回 false。
   */
  function startLinePotential(v) {
    if (v.length === 0) return true; // 下一字节可能是方法/版本首字符或 CR
    for (let i = 0; i < v.length; i++) {
      if (v[i] > 0x7e || (v[i] < SP && v[i] !== HT)) return false;
    }

    // ---- request 前缀 ----
    let i = 0;
    while (i < v.length && isUpperAlpha(v[i])) i++;
    if (i > 0) {
      const word = decodeAscii(v.subarray(0, i));
      if (METHODS.some((m) => m.startsWith(word))) {
        if (i === v.length) return true; // 方法还可能继续
        if (v[i] !== SP) return false;
        i++; // 消费方法后的 SP
        if (i === v.length) return true; // request-target 待定
        while (i < v.length) {
          if (v[i] === SP) break;
          if (!isVChar(v[i])) return false;
          i++;
        }
        if (i === v.length) return true; // 目标未结束 / 版本前的 SP 待定
        i++; // 目标后的 SP
        return HTTP11.startsWith(decodeAscii(v.subarray(i)));
      }
    }

    // ---- response 前缀 ----
    const s = decodeAscii(v);
    if (s.length <= 8) return HTTP11.startsWith(s);
    if (!s.startsWith(HTTP11) || s[8] !== ' ') return false;
    i = 9;
    const digitEnd = Math.min(s.length, i + 3);
    for (let k = i; k < digitEnd; k++) {
      if (!/[0-9]/.test(s[k])) return false;
    }
    if (digitEnd - i < 3) return true; // 状态码第 1..3 位待定
    i += 3;
    if (i === s.length) return true; // 原因短语前的 SP 待定
    if (s[i] !== ' ') return false;
    for (i++; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c !== HT && (c < SP || c > 0x7e)) return false;
    }
    return true;
  }

  /** 去除字段值两侧 OWS（SP/HT）。 */
  function trimOws(b) {
    let lo = 0, hi = b.length;
    while (lo < hi && (b[lo] === SP || b[lo] === HT)) lo++;
    while (hi > lo && (b[hi - 1] === SP || b[hi - 1] === HT)) hi--;
    return b.subarray(lo, hi);
  }

  /** 解析单个头部行（不含 CRLF），返回 {name, value} 或 null（非法头部）。 */
  function parseHeaderLine(line) {
    if (line.length === 0) return null;
    if (line[0] === SP || line[0] === HT) return null; // obs-fold：限定版不接受
    let colon = -1;
    for (let i = 0; i < line.length; i++) {
      if (line[i] === 0x3a) { colon = i; break; }
      if (!isTokenChar(line[i])) return null;
    }
    if (colon <= 0) return null;
    const nameBytes = line.subarray(0, colon);
    const valueBytes = trimOws(line.subarray(colon + 1));
    for (let i = 0; i < valueBytes.length; i++) {
      const b = valueBytes[i];
      // field-content：HT / VCHAR / obs-text（>=0x80）
      if (b !== HT && (b < SP || b === 0x7f)) return null;
    }
    return {
      name: decoder.decode(nameBytes),
      value: decoder.decode(valueBytes)
    };
  }

  /** 在 run 的 [from, runEnd) 内找下一个 CRLF，返回 CR 的展开位置；无则 -1。 */
  function findCRLF(run, from) {
    const bytes = run.bytes;
    const base = run.start;
    for (let i = Math.max(0, from - base); i < bytes.length - 1; i++) {
      if (bytes[i] === CR && bytes[i + 1] === LF) return base + i;
    }
    return -1;
  }

  /** 二分：在按 pos 升序的数组里取 [lo,hi) 内条目的唯一 pktIndex 集合。 */
  function witnessPackets(sortedEvents, lo, hi) {
    if (!sortedEvents.length || hi <= lo) return [];
    let l = 0, r = sortedEvents.length;
    while (l < r) {
      const mid = (l + r) >> 1;
      if (sortedEvents[mid].pos >= lo) r = mid; else l = mid + 1;
    }
    const set = new Set();
    for (let i = l; i < sortedEvents.length && sortedEvents[i].pos < hi; i++) {
      set.add(sortedEvents[i].pktIndex);
    }
    return Array.from(set).sort((a, b) => a - b);
  }

  /** 逐字节归属包号 -> 合并为连续证据段 [{pktIndex,pktNumber,start,end,bytes}]。 */
  function ownerSpans(run, lo, hi) {
    const spans = [];
    let cur = null;
    for (let p = lo; p < hi; p++) {
      const owner = run.owners[p - run.start];
      if (cur && cur.pktIndex === owner) {
        cur.end = p + 1;
        cur.bytes++;
      } else {
        cur = { pktIndex: owner, pktNumber: owner + 1, start: p, end: p + 1, bytes: 1 };
        spans.push(cur);
      }
    }
    return spans;
  }

  /** 取冲突列表（按 pos 升序）中落在 [lo,hi) 内的冲突（附相对位置）。 */
  function conflictsInRange(conflicts, lo, hi, relBase) {
    if (!conflicts.length) return [];
    let l = 0, r = conflicts.length;
    while (l < r) {
      const mid = (l + r) >> 1;
      if (conflicts[mid].pos >= lo) r = mid; else l = mid + 1;
    }
    const out = [];
    for (let i = l; i < conflicts.length && conflicts[i].pos < hi; i++) {
      const c = conflicts[i];
      out.push({
        pos: c.pos,
        relPos: c.pos + relBase,
        keptByte: c.keptByte,
        ownerPkt: c.ownerPkt,
        packets: c.packets
      });
    }
    return out;
  }

  /** 该 run 之后是否紧接缺口（缺口信息由 finalize 给出 gaps）。 */
  function gapAfterRun(run, gaps) {
    for (const g of gaps) {
      if (g.start === run.end) return g;
    }
    return null;
  }

  /**
   * 依据头部决定消息体帧。
   * @returns {{kind:'length',bodyLength:number}
   *          |{kind:'unsupported',reasonCode,reason,encodings}
   *          |{kind:'invalid_length',reason}}
   *
   * 规则（限定版）：
   *   - 任何 Transfer-Encoding => 不支持（chunked 单独点名），不猜边界；
   *   - Content-Length：0 个 => 空体；多个且取值完全一致 => 接受该唯一值；
   *     多个且不一致、非数字、超界 => 未完成（非法 CL）；
   *   - CL 与 TE 同时出现：TE 优先（不支持），不采用 CL 定界。
   */
  function decideFraming(headers) {
    const teRaw = [];
    const clRaw = [];
    for (const h of headers) {
      const name = h.name.toLowerCase();
      if (name === 'transfer-encoding') teRaw.push(h.value);
      else if (name === 'content-length') clRaw.push(h.value);
    }

    if (teRaw.length) {
      const encodings = [];
      teRaw.forEach((v) => v.split(',').forEach((tok) => {
        const t = tok.trim();
        if (t) encodings.push(t);
      }));
      const chunked = encodings.some((t) => t.toLowerCase() === 'chunked');
      return {
        kind: 'unsupported',
        reasonCode: chunked ? 'unsupported_transfer_encoding_chunked' : 'unsupported_transfer_encoding',
        reason: (chunked
          ? '使用分块传输编码（Transfer-Encoding: chunked），限定版不解析其正文边界；'
          : '使用不支持的 Transfer-Encoding（' + encodings.join(', ') + '），限定版不解析其正文边界；') +
          '已标记为不支持，不猜测正文边界、不向后续扫报文。',
        encodings
      };
    }

    if (clRaw.length === 0) {
      return { kind: 'length', bodyLength: 0 };
    }
    if (clRaw.length > 1) {
      const first = clRaw[0];
      if (!clRaw.every((v) => v === first)) {
        return {
          kind: 'invalid_length',
          reason: '存在多个取值不一致的 Content-Length（' + clRaw.map((v) => '"' + v + '"').join(', ') +
            '），消息体长度不明确，报文未完成。'
        };
      }
    }
    const value = clRaw[0];
    if (value.length === 0 || !/^[0-9]+$/.test(value)) {
      return {
        kind: 'invalid_length',
        reason: 'Content-Length 不是明确的非负十进制整数（"' + clRaw[0] + '"），报文未完成。'
      };
    }
    const n = Number(value);
    if (!Number.isSafeInteger(n)) {
      return {
        kind: 'invalid_length',
        reason: 'Content-Length 数值超出可精确表示范围，报文未完成。'
      };
    }
    return { kind: 'length', bodyLength: n };
  }

  function buildMessage(o) {
    const {
      seq, run, lo, hi, relBase, conflicts, retransEvents,
      status, reasonCode, reason, startLine, headers, framing, gap
    } = o;
    return {
      index: seq,
      kind: startLine ? startLine.kind : null,
      status, // 'complete' | 'incomplete' | 'unsupported'
      reasonCode: reasonCode || null,
      reason: reason || null,
      start: lo,
      end: hi,
      relStart: lo + relBase,
      relEnd: hi + relBase,
      presentBytes: hi - lo,
      startLine: startLine ? {
        kind: startLine.kind,
        text: startLine.text,
        method: startLine.method || null,
        target: startLine.target || null,
        statusCode: startLine.statusCode != null ? startLine.statusCode : null,
        reasonPhrase: startLine.reason != null ? startLine.reason : null,
        version: startLine.version
      } : null,
      headers: headers ? headers.map((h) => ({ name: h.name, value: h.value })) : null,
      headerEnd: framing && framing.headerEnd != null ? framing.headerEnd : null,
      bodyStart: framing && framing.bodyStart != null ? framing.bodyStart : null,
      bodyEnd: framing && framing.bodyEnd != null ? framing.bodyEnd : null,
      bodyLengthExpected: framing && framing.bodyLength != null ? framing.bodyLength : null,
      bodyLengthPresent: 0,
      contentLength: framing && framing.contentLength != null ? framing.contentLength : null,
      transferEncoding: framing && framing.transferEncoding ? framing.transferEncoding : null,
      crossesGap: !!gap,
      gap: gap ? {
        start: gap.start, end: gap.end, length: gap.length,
        relStart: gap.start + relBase, relEnd: gap.end + relBase
      } : null,
      evidence: {
        packets: ownerSpans(run, lo, hi),
        retransmitPackets: witnessPackets(retransEvents, lo, hi)
      },
      conflicts: conflictsInRange(conflicts, lo, hi, relBase)
    };
  }

  /**
   * 在 run 内位置 pos 处解析单条报文。
   * 返回：
   *   {stop:false, nextPos, message}          完整/流水线推进
   *   {stop:true,  nextPos, message}          未完成/不支持，后续不可解析
   *   {noCandidate:true}                      起始线不合法，调用方停止本 run
   */
  function parseOne(ctx, pos) {
    const { run, runIndex, gaps, relBase, conflicts, retransEvents } = ctx;
    const mk = (extra) => buildMessage(Object.assign({
      run, lo: pos, relBase, conflicts, retransEvents, startLine: null,
      headers: null, framing: null, gap: null
    }, extra));

    // ---------- 1) 起始行 ----------
    const lineCr = findCRLF(run, pos);
    if (lineCr === -1) {
      const visible = run.bytes.subarray(pos - run.start);
      if (startLinePotential(visible)) {
        return {
          stop: true, nextPos: run.end,
          message: mk({
            seq: null, hi: run.end,
            status: 'incomplete',
            reasonCode: 'truncated_start_line',
            reason: '起始行在连续覆盖区结束处被截断（缺少 CRLF 或未捕获完整），报文未完成。'
          })
        };
      }
      return { noCandidate: true };
    }
    const lineBytes = run.bytes.subarray(pos - run.start, lineCr - run.start);
    const startLine = validStartLine(lineBytes);
    if (!startLine) return { noCandidate: true };
    let p = lineCr + 2;

    // ---------- 2) 头部块（每条头部必须有完整 CRLF，空行结束）----------
    const headers = [];
    let headerEnd = -1;
    while (true) {
      const hCr = findCRLF(run, p);
      if (hCr === -1) {
        return {
          stop: true, nextPos: run.end,
          message: mk({
            seq: null, hi: run.end, status: 'incomplete',
            reasonCode: 'truncated_header_block',
            reason: '头部块在连续覆盖区结束处被截断（缺少结束头部的空行 CRLF），报文未完成。',
            startLine, headers,
            framing: { headerEnd: null }
          })
        };
      }
      const hLine = run.bytes.subarray(p - run.start, hCr - run.start);
      p = hCr + 2;
      if (hLine.length === 0) { headerEnd = hCr + 2; break; }
      if (headers.length >= MAX_HEADERS) {
        return {
          stop: true, nextPos: p,
          message: mk({
            seq: null, hi: p, status: 'incomplete',
            reasonCode: 'too_many_headers',
            reason: '头部数量超过限定版上限 ' + MAX_HEADERS + '，停止解析该报文。',
            startLine, headers, framing: { headerEnd: p }
          })
        };
      }
      const h = parseHeaderLine(hLine);
      if (!h) {
        return {
          stop: true, nextPos: p,
          message: mk({
            seq: null, hi: p, status: 'incomplete',
            reasonCode: 'malformed_header',
            reason: '存在不合法的头部行（字段名/字段值非法或折行 obs-fold），报文未完成。',
            startLine, headers, framing: { headerEnd: p }
          })
        };
      }
      headers.push(h);
    }

    // ---------- 3) 帧定界：只支持明确的 Content-Length ----------
    const framing = decideFraming(headers);
    if (framing.kind === 'unsupported') {
      const msg = mk({
        seq: null, hi: headerEnd, status: 'unsupported',
        reasonCode: framing.reasonCode, reason: framing.reason,
        startLine, headers,
        framing: { headerEnd, bodyStart: null, bodyEnd: null, bodyLength: null, transferEncoding: framing.encodings }
      });
      return { stop: true, nextPos: headerEnd, message: msg };
    }
    if (framing.kind === 'invalid_length') {
      const msg = mk({
        seq: null, hi: headerEnd, status: 'incomplete',
        reasonCode: 'invalid_content_length', reason: framing.reason,
        startLine, headers,
        framing: { headerEnd, bodyStart: null, bodyEnd: null, bodyLength: null }
      });
      return { stop: true, nextPos: headerEnd, message: msg };
    }

    // kind === 'length'：bodyLength 为明确的非负整数（0 表示无消息体）。
    const bodyLength = framing.bodyLength;
    const bodyStart = headerEnd;
    const bodyEnd = headerEnd + bodyLength;
    const framingOut = { headerEnd, bodyStart, bodyEnd, bodyLength, contentLength: bodyLength };

    // ---------- 4) 消息体覆盖核验：不得越过本连续 run（缺口 / 截断）----------
    if (bodyEnd > run.end) {
      const g = gapAfterRun(run, gaps);
      const msg = mk({
        seq: null, hi: run.end, status: 'incomplete',
        reasonCode: g ? 'body_crosses_gap' : 'truncated_body',
        reason:
          'Content-Length 声明正文 ' + bodyLength + ' 字节，但连续覆盖区在正文第 ' +
          (run.end - bodyStart + 1) + ' 字节后结束' +
          (g ? '（其后是 ' + g.length + ' 字节缺口）' : '（捕获在此结束）') +
          '；报文未完成，未把缺口另一侧字节拼入。',
        startLine, headers, framing: framingOut, gap: g
      });
      msg.bodyEnd = bodyEnd; // 声明的（不可达）边界，presentBytes 仍只算连续部分
      msg.bodyLengthPresent = Math.max(0, run.end - bodyStart);
      return { stop: true, nextPos: run.end, message: msg };
    }

    // 全部帧字节落在同一个连续 run 内。区间内有冲突位置 => 字节事实不唯一，
    // 即使语法完整也只能标未完成，不能输出伪完整报文。
    const inRangeConflicts = conflictsInRange(conflicts, pos, bodyEnd, relBase);
    const msg = mk({
      seq: null, hi: bodyEnd,
      status: inRangeConflicts.length ? 'incomplete' : 'complete',
      reasonCode: inRangeConflicts.length ? 'conflict_in_message' : null,
      reason: inRangeConflicts.length
        ? '报文区间内存在 ' + inRangeConflicts.length + ' 个字节冲突位置，内容不唯一，不能作为确定报文输出。'
        : null,
      startLine, headers, framing: framingOut
    });
    msg.bodyLengthPresent = bodyLength;
    return { stop: false, nextPos: bodyEnd, message: msg };
  }

  /**
   * 解析一个方向的 HTTP/1.1 报文。
   * @param {Object} dir finalize 后的单方向模型：
   *   runs: [{start,end,relStart,relEnd,bytes,owners}], gaps, conflicts, relBase，
   *   retransEvents: [{pos,pktIndex}]（按 pos 升序）
   * @returns {{messages:Array, notices:Array}}
   */
  function parseDirection(dir) {
    const runs = dir.runs || [];
    const conflicts = dir.conflicts || [];
    const gaps = dir.gaps || [];
    const relBase = dir.relBase || 0;
    const retransEvents = dir.retransEvents || [];
    const messages = [];
    const notices = [];
    let seq = 0;
    const ctxBase = { gaps, relBase, conflicts, retransEvents };

    runs.forEach((run, runIndex) => {
      const ctx = Object.assign({ run, runIndex }, ctxBase);
      let pos = run.start;

      // ---- run 起始处最多一次起始线再同步 ----
      // run 起点本身可能是某条报文中点（上一报文在缺口另一侧）。只有当 run 起点
      // 不是合法起始线时，才向 run 内部搜索第一条“完整合法起始线”；跳过字节
      // 显式留痕。绝不跨缺口向另一侧寻找起始线。
      const firstCr = findCRLF(run, pos);
      let firstLineValid = false;
      if (firstCr !== -1) {
        firstLineValid = !!validStartLine(run.bytes.subarray(0, firstCr - run.start));
      }
      if (!firstLineValid) {
        let found = -1;
        if (firstCr !== -1) {
          // run 第一行（[run 起点, 第一个 CRLF)）可能是“少量杂散字节 + 一条完整
          // 合法起始线”（如上一帧残余与本帧起始线落在同一连续段内）。逐位置尝试：
          // 仅当从该位置到该 CRLF 恰好是一条完整合法起始线时才再同步；
          // 绝不向第二行及之后扫描（避免把后续合法报文误判为前缀后的目标）。
          for (let cand = pos; cand < firstCr; cand++) {
            const candidate = run.bytes.subarray(cand - run.start, firstCr - run.start);
            if (validStartLine(candidate)) { found = cand; break; }
          }
        }
        if (found === -1) {
          // run 第一行不是、也不包含合法起始线。仅当 run 中没有任何 CRLF
          // （整段像被截断的起始线）时，标一条未完成候选；否则第一行就是
          // 无法识别内容，本 run 不产出 HTTP 报文（不猜测）。
          if (firstCr === -1 && run.bytes.length > 0 && startLinePotential(run.bytes)) {
            const m = buildMessage({
              seq: ++seq, run, lo: run.start, hi: run.end, relBase, conflicts, retransEvents,
              status: 'incomplete', reasonCode: 'truncated_start_line',
              reason: '起始行在连续覆盖区结束处被截断（缺少 CRLF），报文未完成；缺口另一侧的字节未参与拼接。',
              startLine: null, headers: null, framing: null, gap: null
            });
            messages.push(m);
          } else if (firstCr !== -1) {
            notices.push({
              type: 'unparsed_trailing',
              runIndex,
              start: pos, end: run.end,
              relStart: pos + relBase, relEnd: run.end + relBase,
              length: run.end - pos,
              message: '连续覆盖段 #' + runIndex + ' 起始处不是合法 HTTP/1.1 起始线，不产出报文、不猜测边界。'
            });
          }
          return;
        }
        if (found > pos) {
          notices.push({
            type: 'skipped_prefix',
            runIndex,
            start: pos, end: found,
            relStart: pos + relBase, relEnd: found + relBase,
            length: found - pos,
            message: '连续覆盖段 #' + runIndex + ' 起始 ' + (found - pos) +
              ' 字节不是合法 HTTP/1.1 起始线，已跳过并在相对序号 ' + (found + relBase) +
              ' 重新同步；跳过字节未计入任何报文。'
          });
        }
        pos = found;
      }

      // ---- run 内逐条扫描（支持同 run 内流水线多条报文）----
      while (pos < run.end) {
        const r = parseOne(ctx, pos);
        if (r.noCandidate) {
          notices.push({
            type: 'unparsed_trailing',
            runIndex,
            start: pos, end: run.end,
            relStart: pos + relBase, relEnd: run.end + relBase,
            length: run.end - pos,
            message: '自相对序号 ' + (pos + relBase) + ' 起的 ' + (run.end - pos) +
              ' 字节不是合法 HTTP/1.1 起始线，停止本连续段扫描，剩余字节不解析、不拼接到任何报文。'
          });
          return;
        }
        r.message.index = ++seq;
        messages.push(r.message);
        if (r.stop) {
          if (r.nextPos < run.end) {
            notices.push({
              type: 'unparsed_trailing',
              runIndex,
              start: r.nextPos, end: run.end,
              relStart: r.nextPos + relBase, relEnd: run.end + relBase,
              length: run.end - r.nextPos,
              message: r.message.status === 'unsupported'
                ? '不支持的传输编码，正文边界不可知；本连续段后续 ' + (run.end - r.nextPos) +
                  ' 字节不解析，避免猜测报文边界。'
                : '报文未完成，帧边界不可确定；本连续段后续 ' + (run.end - r.nextPos) +
                  ' 字节不解析，避免猜测报文边界。'
            });
          }
          return;
        }
        pos = r.nextPos;
      }
    });

    return { messages, notices, parseVersion: 'http11-limited-v1' };
  }

  /**
   * 入口：finalize 的方向模型（含 gaps）直接可用。
   */
  function analyze(direction) {
    return parseDirection(direction);
  }

  return { analyze, parseDirection, validStartLine, decideFraming };
});
