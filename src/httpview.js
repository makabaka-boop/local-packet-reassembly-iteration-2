/*
 * 限定版 HTTP/1.1 报文识别。
 *
 * 与重组层一致的原则：只展示事实，不猜测。
 *   - 仅在单个覆盖 run（连续字节）内识别报文；绝不跨缺口拼接——
 *     缺口两侧的字节不会被拼成一条“看起来完整”的报文；
 *   - 报文区间内存在冲突字节 => 标为未完成（保留字节的归属有争议）；
 *   - 仅支持显式 Content-Length 界定的正文：
 *       · Transfer-Encoding（chunked 等）=> 明确标为不支持，不猜测正文边界；
 *       · 响应未声明 Content-Length 且按状态码可以有正文 => 不支持
 *         （其边界依赖连接关闭，限定版不猜测）；
 *       · 请求无 Content-Length / Transfer-Encoding => 正文长度按 0 处理（RFC 9112）；
 *       · 1xx / 204 / 304 响应按定义无正文 => 正文长度 0；
 *   - 声明长度超出已捕获字节、头部未完整、捕获中途结束 => 未完成；
 *   - 每个报文给出在方向流中的字节区间（展开坐标）与属主包号证据；
 *   - 分析按“方向 × 会话”进行：同四元组的后续会话是独立的连接实例，
 *     其 HTTP 分析只面向本会话的字节，不会续接前一会话的残余报文。
 *
 * 可被 Worker 与 Node 测试同时加载。
 */
(function (global, factory) {
  const api = factory();
  global.HttpViewLib = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const CR = 0x0d;
  const LF = 0x0a;
  const MAX_LINE = 8192; // 限定版：起始行 / 头部行长度上限
  const MAX_HEADERS = 100; // 限定版：单报文头部行数上限
  const MAX_CL_DIGITS = 15; // Content-Length 位数上限（超出则无法精确表示）

  // 起始行：严格单空格分隔、版本为 HTTP/x.y；方法为不含小写的 token（实际方法均为大写）。
  const RE_STATUS = /^HTTP\/(\d+)\.(\d+) ([0-9]{3})( (.*))?$/;
  const RE_REQUEST = /^([A-Z0-9!#$%&'*+\-.^_`|~]{1,32}) ([!-~]+) (HTTP\/(\d+)\.(\d+))$/;
  const RE_HEADER_NAME = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;
  const RE_DIGITS = /^\d+$/;
  // 已捕获的部分是否像 HTTP/1.1 起始行的前缀（用于“起始行未完整”的候选判定）。
  const RE_PARTIAL_START = /^HTTP\//;
  const RE_PARTIAL_METHOD = /^[A-Z][A-Z0-9!#$%&'*+\-.^_`|~]{0,31} /;

  /** 取 run 内 [a, b)（展开坐标）的字节，按 Latin-1 逐字节转字符串。 */
  function bytesToString(run, a, b) {
    let s = '';
    for (let p = a; p < b; p++) s += String.fromCharCode(run.bytes[p - run.start]);
    return s;
  }

  /**
   * 在 run 内从 pos 读一行（必须以 CRLF 结束）。
   * 返回 { ok:true, start, end(不含CRLF), next } |
   *       { ok:false, needMore:true }（run 内没有完整行） |
   *       { ok:false, malformed:'原因' }
   */
  function readLine(run, pos) {
    const bytes = run.bytes;
    const base = run.start;
    let i = pos;
    while (i < run.end) {
      if (i - pos >= MAX_LINE) {
        return { ok: false, malformed: '行超过限定版 ' + MAX_LINE + ' 字节上限' };
      }
      const b = bytes[i - base];
      if (b === CR) {
        if (i + 1 >= run.end) return { ok: false, needMore: true };
        if (bytes[i + 1 - base] === LF) return { ok: true, start: pos, end: i, next: i + 2 };
        return { ok: false, malformed: 'CR 后未紧跟 LF' };
      }
      if (b === LF) return { ok: false, malformed: '裸 LF（前面没有 CR）' };
      i++;
    }
    return { ok: false, needMore: true };
  }

  /**
   * 解析起始行。返回 { kind:'request'|'response', ... , wrongVersion } 或 null。
   * 形状合法但版本不是 HTTP/1.1 时 wrongVersion=true（由调用方如实标注，不冒充）。
   */
  function parseStartLine(s) {
    let m = RE_STATUS.exec(s);
    if (m) {
      const version = 'HTTP/' + m[1] + '.' + m[2];
      return {
        kind: 'response',
        version,
        statusCode: parseInt(m[3], 10),
        reasonPhrase: m[5] || '',
        wrongVersion: version !== 'HTTP/1.1'
      };
    }
    m = RE_REQUEST.exec(s);
    if (m) {
      return {
        kind: 'request',
        version: m[3],
        method: m[1],
        target: m[2],
        wrongVersion: m[3] !== 'HTTP/1.1'
      };
    }
    return null;
  }

  /** 解析一行头部。返回 { name, value } 或 { error }。 */
  function parseHeaderLine(s) {
    if (s.charAt(0) === ' ' || s.charAt(0) === '\t') {
      return { error: '头部行以空白开头（obs-fold 折叠行），限定版不支持折叠' };
    }
    const colon = s.indexOf(':');
    if (colon <= 0) return { error: '缺少字段名或冒号' };
    const name = s.slice(0, colon);
    if (!RE_HEADER_NAME.test(name)) return { error: '字段名含非法字符' };
    const value = s.slice(colon + 1).replace(/^[\t ]+/, '').replace(/[\t ]+$/, '');
    for (let i = 0; i < value.length; i++) {
      const c = value.charCodeAt(i);
      if (!(c === 0x09 || (c >= 0x20 && c <= 0x7e) || c >= 0x80)) {
        return { error: '字段值含非法控制字符' };
      }
    }
    return { name, value };
  }

  /**
   * 汇总所有 Content-Length 值（含逗号列表）。全部一致才合法（RFC 9112）。
   * 返回 { value } | { error } | { huge, raw }（位数过多无法精确表示）。
   */
  function parseContentLength(values) {
    const nums = [];
    for (const v of values) {
      const parts = v.split(',');
      for (let part of parts) {
        part = part.replace(/^[\t ]+/, '').replace(/[\t ]+$/, '');
        if (!RE_DIGITS.test(part)) {
          return { error: 'Content-Length 值不是合法十进制数："' + v + '"' };
        }
        if (part.length > MAX_CL_DIGITS) return { huge: true, raw: part };
        nums.push(parseInt(part, 10));
      }
    }
    for (let i = 1; i < nums.length; i++) {
      if (nums[i] !== nums[0]) {
        return { error: '多个 Content-Length 值不一致：' + nums.join('、') };
      }
    }
    return { value: nums[0] };
  }

  function countConflicts(conflictPositions, a, b) {
    let n = 0;
    for (const p of conflictPositions) if (p >= a && p < b) n++;
    return n;
  }

  /** 区间 [a, b) 内字节的属主包（文件中先捕获者），按流内位置顺序去重。 */
  function evidencePackets(run, a, b) {
    const out = [];
    const sources = run.sources || [];
    for (const s of sources) {
      if (s.end <= a) continue;
      if (s.start >= b) break;
      if (!out.length || out[out.length - 1] !== s.pktIndex) out.push(s.pktIndex);
    }
    return out;
  }

  /** 未识别区域的短预览：可打印字符原样，其余以 '.' 代替。 */
  function previewBytes(run, a, b) {
    const max = 48;
    const n = Math.min(b - a, max);
    let s = '';
    for (let i = 0; i < n; i++) {
      const c = run.bytes[a - run.start + i];
      s += c >= 0x20 && c <= 0x7e ? String.fromCharCode(c) : '.';
    }
    if (b - a > max) s += '…';
    return s;
  }

  /** 冲突检查：区间内有冲突字节 => 一律按未完成处理（保留字节有争议）。 */
  function finishConflictCheck(msg, ctx, a, b) {
    const n = countConflicts(ctx.conflictPositions, a, b);
    if (n > 0) {
      msg.status = 'incomplete';
      msg.reasons.push('报文区间内存在 ' + n + ' 处字节冲突，保留字节有争议，按未完成处理');
    }
  }

  function invalidMessage(msg, run, ctx, reason, capturedEnd) {
    msg.status = 'invalid';
    msg.reasons.push(reason);
    msg.capturedEnd = capturedEnd;
    msg.packets = evidencePackets(run, msg.range.start, capturedEnd);
    return { message: msg };
  }

  function makeMessage(kind) {
    return {
      index: -1,
      kind,
      status: 'complete',
      startLine: null,
      partialStartLine: null,
      method: null,
      target: null,
      statusCode: null,
      reasonPhrase: null,
      httpVersion: null,
      headers: [],
      contentLength: null,
      transferEncoding: null,
      bodyLength: null,
      range: { start: 0, headerEnd: null, bodyStart: null, end: null },
      declaredEnd: null,
      capturedEnd: null,
      packets: [],
      reasons: []
    };
  }

  /**
   * 在 run 内从 pos 尝试识别一条报文。
   * 返回 { message }（含未完成/不支持/非法候选）或 { unrecognized:'原因' }。
   */
  function parseMessageAt(run, pos, ctx) {
    const first = readLine(run, pos);
    if (!first.ok) {
      if (first.needMore) {
        const partial = bytesToString(run, pos, run.end);
        if (RE_PARTIAL_START.test(partial) || RE_PARTIAL_METHOD.test(partial)) {
          // 起始行未完整：像 HTTP 但缺 CRLF，作为未完成候选如实展示。
          const msg = makeMessage('unknown');
          msg.status = 'incomplete';
          msg.range.start = pos;
          msg.partialStartLine = partial.length > 80 ? partial.slice(0, 80) + '…' : partial;
          msg.reasons.push('起始行未完整：捕获中缺少 CRLF 行结束' + ctx.tailNote);
          msg.capturedEnd = run.end;
          finishConflictCheck(msg, ctx, pos, run.end);
          msg.packets = evidencePackets(run, pos, run.end);
          return { message: msg };
        }
        return { unrecognized: '起始行未完整，且已捕获部分不像 HTTP/1.1 起始行' };
      }
      return { unrecognized: '起始行不合法：' + first.malformed };
    }

    const startLineStr = bytesToString(run, first.start, first.end);
    const sl = parseStartLine(startLineStr);
    if (!sl) return { unrecognized: '起始行不是合法的 HTTP/1.1 请求行或状态行' };
    if (sl.wrongVersion) {
      return { unrecognized: '起始行版本为 ' + sl.version + '，限定版仅识别 HTTP/1.1' };
    }

    const msg = makeMessage(sl.kind);
    msg.startLine = startLineStr;
    msg.method = sl.method || null;
    msg.target = sl.target || null;
    msg.statusCode = sl.statusCode !== undefined ? sl.statusCode : null;
    msg.reasonPhrase = sl.reasonPhrase !== undefined ? sl.reasonPhrase : null;
    msg.httpVersion = sl.version;
    msg.range.start = pos;

    // ---- CRLF 头部：逐行解析，空行（CRLF）结束 ----
    let p = first.next;
    let headerEnd = null;
    for (let n = 0; ; n++) {
      if (n >= MAX_HEADERS) {
        return invalidMessage(msg, run, ctx, '头部行数超过限定版上限 ' + MAX_HEADERS, p);
      }
      const ln = readLine(run, p);
      if (!ln.ok) {
        if (ln.needMore) {
          msg.status = 'incomplete';
          msg.reasons.push('头部未完整：CRLF 头终止序列未出现在捕获中' + ctx.tailNote);
          msg.capturedEnd = run.end;
          finishConflictCheck(msg, ctx, pos, run.end);
          msg.packets = evidencePackets(run, pos, run.end);
          return { message: msg };
        }
        return invalidMessage(msg, run, ctx, '头部行不合法：' + ln.malformed, run.end);
      }
      if (ln.end === ln.start) {
        headerEnd = ln.next;
        break;
      }
      const h = parseHeaderLine(bytesToString(run, ln.start, ln.end));
      if (h.error) return invalidMessage(msg, run, ctx, '头部行不合法：' + h.error, ln.next);
      msg.headers.push({ name: h.name, value: h.value });
      p = ln.next;
    }
    msg.range.headerEnd = headerEnd;
    msg.range.bodyStart = headerEnd;

    // ---- 正文框架：仅支持显式 Content-Length ----
    const clValues = [];
    for (const h of msg.headers) {
      const name = h.name.toLowerCase();
      if (name === 'content-length') clValues.push(h.value);
      else if (name === 'transfer-encoding') msg.transferEncoding = h.value;
    }

    if (msg.transferEncoding !== null) {
      msg.status = 'unsupported';
      msg.reasons.push(
        'Transfer-Encoding: ' + msg.transferEncoding +
          ' —— 分块等传输编码不在限定版支持范围内，未猜测正文边界'
      );
      msg.range.end = headerEnd; // 只有头部区间是可确定的事实
      msg.capturedEnd = headerEnd;
      finishConflictCheck(msg, ctx, pos, headerEnd);
      msg.packets = evidencePackets(run, pos, headerEnd);
      return { message: msg };
    }

    let bodyLen;
    if (clValues.length) {
      const cl = parseContentLength(clValues);
      if (cl.error) return invalidMessage(msg, run, ctx, cl.error, headerEnd);
      if (cl.huge) {
        msg.status = 'incomplete';
        msg.reasons.push(
          'Content-Length 数值（' + cl.raw + '）超出可精确表示范围，捕获不可能完整，按未完成处理'
        );
        msg.capturedEnd = run.end;
        finishConflictCheck(msg, ctx, pos, run.end);
        msg.packets = evidencePackets(run, pos, run.end);
        return { message: msg };
      }
      bodyLen = cl.value;
      msg.contentLength = cl.value;
    } else if (msg.kind === 'request') {
      bodyLen = 0; // RFC 9112：请求无 CL/TE 即无正文
    } else {
      const code = msg.statusCode;
      if ((code >= 100 && code < 200) || code === 204 || code === 304) {
        bodyLen = 0; // 按定义无正文的响应
      } else {
        msg.status = 'unsupported';
        msg.reasons.push('响应未声明 Content-Length，正文边界依赖连接关闭，限定版不猜测');
        msg.range.end = headerEnd;
        msg.capturedEnd = headerEnd;
        finishConflictCheck(msg, ctx, pos, headerEnd);
        msg.packets = evidencePackets(run, pos, headerEnd);
        return { message: msg };
      }
    }

    msg.bodyLength = bodyLen;
    const declaredEnd = headerEnd + bodyLen;
    msg.declaredEnd = declaredEnd;
    msg.range.end = declaredEnd;

    let capturedEnd = declaredEnd;
    if (declaredEnd > run.end) {
      // 长度不完整：声明的正文超出本 run 的连续字节，绝不向缺口/后续 run 拼接。
      capturedEnd = run.end;
      msg.status = 'incomplete';
      const have = run.end - headerEnd;
      msg.reasons.push(
        '声明 Content-Length ' + bodyLen + ' 字节正文，捕获内连续字节仅剩 ' + have +
          '（缺 ' + (bodyLen - have) + ' 字节）' + ctx.tailNote
      );
    }
    msg.capturedEnd = capturedEnd;
    finishConflictCheck(msg, ctx, pos, capturedEnd);
    msg.packets = evidencePackets(run, pos, capturedEnd);
    return { message: msg };
  }

  const STATUS_WORD = { incomplete: '未完成', unsupported: '不支持', invalid: '非法' };

  /**
   * 分析一个方向的重组结果。
   * @param {Object} dir reassemble.js finalize() 的方向对象（runs 含 sources）
   * @returns {{messages:Array, unrecognized:Array, summary:Object}}
   */
  function analyzeDirection(dir) {
    const messages = [];
    const unrecognized = [];
    const runs = (dir && dir.runs) || [];
    const gaps = (dir && dir.gaps) || [];
    const conflictPositions = ((dir && dir.conflicts) || []).map((c) => c.pos);

    runs.forEach((run, ri) => {
      const isLastRun = ri === runs.length - 1;
      const gapAfter = gaps.find((g) => g.start === run.end) || null;
      // 区间之外是什么（缺口 / 捕获结束），写进未完成原因，便于取证核对。
      const tailNote = gapAfter
        ? '；区间之后为缺口（' + gapAfter.length + ' 字节），不得跨缺口拼接'
        : isLastRun
          ? '；之后捕获结束（文件截断或连接未继续）'
          : '';

      let pos = run.start;
      while (pos < run.end) {
        const res = parseMessageAt(run, pos, { conflictPositions, tailNote });
        if (res.unrecognized) {
          unrecognized.push({
            start: pos,
            end: run.end,
            reason: res.unrecognized,
            preview: previewBytes(run, pos, run.end)
          });
          break;
        }
        const msg = res.message;
        msg.index = messages.length;
        messages.push(msg);
        if (msg.status === 'complete') {
          pos = msg.range.end; // 完整报文边界确定，可继续识别下一条（流水线）
          continue;
        }
        // 非完整报文：边界不可知，本 run 剩余字节不做猜测性识别。
        if (msg.capturedEnd < run.end) {
          unrecognized.push({
            start: msg.capturedEnd,
            end: run.end,
            reason: '位于上一' + (STATUS_WORD[msg.status] || '未完成') + '报文之后，边界不可知，未做识别',
            preview: previewBytes(run, msg.capturedEnd, run.end)
          });
        }
        break;
      }
    });

    const summary = { complete: 0, incomplete: 0, unsupported: 0, invalid: 0, unrecognizedBytes: 0 };
    for (const m of messages) summary[m.status]++;
    for (const u of unrecognized) summary.unrecognizedBytes += u.end - u.start;
    return { messages, unrecognized, summary };
  }

  /**
   * 对整个重组模型执行 HTTP 分析，结果挂在每个方向的 .http 上。
   * 在 Worker 内于冻结快照之前调用，使页面展示与 JSON 导出引用同一份结果。
   */
  function annotateModel(model) {
    if (!model || !model.connections) return model;
    for (const conn of model.connections) {
      if (conn.directionAtoB) conn.directionAtoB.http = analyzeDirection(conn.directionAtoB);
      if (conn.directionBtoA) conn.directionBtoA.http = analyzeDirection(conn.directionBtoA);
    }
    return model;
  }

  return { analyzeDirection, annotateModel };
});
