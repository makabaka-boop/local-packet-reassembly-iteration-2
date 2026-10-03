/*
 * 解析 Worker：所有字节处理都在本线程内完成，文件绝不上传。
 * 主线程通过递增 token 标识“当前会话”；旧 Worker 的迟到结果由主线程忽略，
 * 重新导入 / 取消时旧 Worker 会被 terminate()。
 *
 * 消息协议：
 *   主线程 -> Worker : { type: 'parse', token, buffer(ArrayBuffer), fileName, fileSize, maxPackets }
 *   Worker -> 主线程 : { type: 'result', token, ok:true, snapshot, model }
 *                      { type: 'result', token, ok:false, fatal, message, evidence? }
 */
'use strict';

try {
  importScripts('pcap.js', 'http.js', 'reassemble.js');
} catch (e) {
  // importScripts 路径错误时给出明确错误，而不是静默失败。
  self.postMessage({
    type: 'result',
    token: null,
    ok: false,
    fatal: true,
    message: 'Worker 依赖脚本加载失败：' + e.message
  });
}

self.onmessage = function (ev) {
  const msg = ev.data;
  if (!msg || msg.type !== 'parse') return;
  const { token, buffer, fileName, fileSize, maxPackets } = msg;

  try {
    const bytes = new Uint8Array(buffer);
    // 纵深防御：即便调用方未提前拦截，Worker 内也强制限定版上限。
    const MAX_FILE_BYTES = 8 * 1024 * 1024;
    if (bytes.byteLength > MAX_FILE_BYTES) {
      self.postMessage({
        type: 'result',
        token,
        ok: false,
        fatal: true,
        message:
          '文件为 ' + bytes.byteLength.toLocaleString() + ' 字节，超过限定版 8 MB 上限，已拒绝解析。'
      });
      return;
    }
    const parsed = self.PcapLib.parse(bytes, { maxPackets: maxPackets || 2000 });
    const model = self.ReassemblyLib.buildModel(parsed, bytes);

    // 解析一完成即冻结；页面选中项、JSON 导出都只引用这一份不可变快照
    // （model 不再单独回传，杜绝“实时模型与冻结快照两份不一致”的可能）。
    const snapshot = self.ReassemblyLib.freezeModel(model, {
      fileName: fileName || '(未命名)',
      fileSize: fileSize != null ? fileSize : bytes.byteLength,
      parsedAt: new Date().toISOString()
    });

    // 冻结快照中的 run.bytes / owners 已展开为普通数组，可结构化克隆直接回传。
    self.postMessage({ type: 'result', token, ok: true, snapshot });
  } catch (err) {
    const isFatal = !!(err && err.fatal);
    self.postMessage({
      type: 'result',
      token,
      ok: false,
      fatal: isFatal,
      message: (err && err.message) || String(err),
      evidence: err && err.evidence ? err.evidence : null
    });
  }
};
