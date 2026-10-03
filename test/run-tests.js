/*
 * Node 对拍测试：用手工构造的小端 PCAP 样本验证解析与重组。
 * 覆盖：乱序、重传（相同去重 / 不同冲突）、缺口、序号回绕、
 *      文件头整份拒绝、截断包留证据、2000 包上限、非 IPv4/TCP、snaplen 截断。
 *
 * 运行：node test/run-tests.js
 */
'use strict';

const assert = require('assert');
const PcapLib = require('../src/pcap.js');
const ReassemblyLib = require('../src/reassemble.js');

// ---------------- 样本 PCAP 构造器 ----------------

const GLOBAL_HEADER = Buffer.from([
  0xd4, 0xc3, 0xb2, 0xa1, // 小端经典 pcap 魔数
  0x02, 0x00, 0x04, 0x00, // 2.4
  0x00, 0x00, 0x00, 0x00, // thiszone
  0x00, 0x00, 0x00, 0x00, // sigfigs
  0xff, 0xff, 0x00, 0x00, // snaplen 65535
  0x01, 0x00, 0x00, 0x00 // LINKTYPE_ETHERNET
]);

function ipv4ToBytes(ip) {
  return ip.split('.').map(Number);
}

function buildTcp({ seq, ack = 0, flags = 0x10, payload = Buffer.alloc(0), srcPort, dstPort }) {
  const dataOffset = 20;
  const buf = Buffer.alloc(20 + payload.length);
  buf.writeUInt16BE(srcPort, 0);
  buf.writeUInt16BE(dstPort, 2);
  buf.writeUInt32BE(seq >>> 0, 4);
  buf.writeUInt32BE(ack >>> 0, 8);
  buf[12] = (dataOffset / 4) << 4;
  buf[13] = flags;
  buf.writeUInt16BE(0, 14); // window
  buf.writeUInt16BE(0, 16); // checksum（不校验）
  buf.writeUInt16BE(0, 18); // urgent
  payload.copy(buf, 20);
  return buf;
}

function buildIpv4({ srcIp, dstIp, protocol = 6, payload }) {
  const ihl = 20;
  const totalLen = ihl + payload.length;
  const buf = Buffer.alloc(ihl + payload.length);
  buf[0] = 0x45; // v4 + IHL 5
  buf[1] = 0;
  buf.writeUInt16BE(totalLen, 2);
  buf.writeUInt16BE(0, 4); // id
  buf.writeUInt16BE(0, 6); // flags/frag
  buf[8] = 64; // ttl
  buf[9] = protocol;
  buf.writeUInt16BE(0, 10); // checksum
  Buffer.from(ipv4ToBytes(srcIp)).copy(buf, 12);
  Buffer.from(ipv4ToBytes(dstIp)).copy(buf, 16);
  payload.copy(buf, 20);
  return buf;
}

function buildEther({ ethertype = 0x0800, payload }) {
  const buf = Buffer.alloc(14 + payload.length);
  // dst MAC [0..5] / src MAC [6..11] 任意；EtherType 在 [12..13]（网络字节序）
  buf[12] = (ethertype >> 8) & 0xff;
  buf[13] = ethertype & 0xff;
  payload.copy(buf, 14);
  return buf;
}

let tsCounter = 1000000;
function pcapRecord(frame, { inclLen = null, origLen = null } = {}) {
  const data = inclLen === null ? frame : frame.slice(0, inclLen);
  const rec = Buffer.alloc(16 + data.length);
  const tsSec = Math.floor(tsCounter / 1000000);
  const tsUsec = tsCounter % 1000000;
  tsCounter += 1000;
  rec.writeUInt32LE(tsSec, 0);
  rec.writeUInt32LE(tsUsec, 4);
  rec.writeUInt32LE(data.length, 8);
  rec.writeUInt32LE(origLen === null ? frame.length : origLen, 12);
  data.copy(rec, 16);
  return rec;
}

function buildPcap(records, { globalHeader = GLOBAL_HEADER } = {}) {
  return Buffer.concat([globalHeader, ...records]);
}

const FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };

function tcpPkt({
  seq,
  ack = 0,
  flags = FLAGS.ACK,
  payload = Buffer.alloc(0),
  srcIp = '10.0.0.1',
  dstIp = '10.0.0.2',
  srcPort = 1111,
  dstPort = 80,
  ethertype = 0x0800,
  protocol = 6,
  inclLen = null,
  origLen = null
} = {}) {
  let frame;
  if (ethertype === 0x0800) {
    const tcp = buildTcp({ seq, ack, flags, payload, srcPort, dstPort });
    const ip = buildIpv4({ srcIp, dstIp, protocol, payload: tcp });
    frame = buildEther({ ethertype, payload: ip });
  } else {
    frame = buildEther({ ethertype, payload: Buffer.alloc(20) });
  }
  return pcapRecord(frame, { inclLen, origLen });
}

function parseBuf(buf, opts) {
  return PcapLib.parse(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), opts);
}
function buildFromBuf(buf, opts) {
  const parsed = parseBuf(buf, opts);
  const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  return { parsed, model: ReassemblyLib.buildModel(parsed, bytes) };
}
function runText(model, connIndex, dir) {
  const conn = model.connections[connIndex];
  return (dir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA).text;
}
function runBytes(model, connIndex, dir) {
  const conn = model.connections[connIndex];
  const d = dir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA;
  return Buffer.concat(d.runs.map((r) => Buffer.from(r.bytes)));
}

// ---------------- 测试用例 ----------------

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

test('乱序 + 相同重传去重 + 字节冲突 + 缺口（单方向对拍）', () => {
  // ISN = 1000；展开坐标 0 为 SYN，数据字节位于 1..10。乱序到达：
  //  包1 SYN(seq=1000)
  //  包2 seq=1005 payload full[4..7]      先捕获中段（位置 5..8）
  //  包3 seq=1001 payload full[0..3]      后捕获首段（位置 1..4）
  //  包4 seq=1004 payload "XX" 位置4,5     位置4 与包3冲突（包3先捕获，保留 full[3]）
  //                                        位置5 与包2冲突（包2先捕获，保留 full[4]）
  //  包5 seq=1005 payload full[4..7]      与包2完全相同 => 重传去重 4 字节
  //  包6 seq=1010 payload full[9]         位置10；位置9（full[8]）缺失 => 缺口
  tsCounter = 1000000;
  const full = Buffer.from('ABCDEFGHIJ');
  const recs = [
    tcpPkt({ seq: 1000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 1005, payload: full.slice(4, 8) }),
    tcpPkt({ seq: 1001, payload: full.slice(0, 4) }),
    tcpPkt({ seq: 1004, payload: Buffer.from('XX') }),
    tcpPkt({ seq: 1005, payload: full.slice(4, 8) }),
    tcpPkt({ seq: 1010, payload: full.slice(9, 10) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));

  assert.strictEqual(model.connections.length, 1);
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.coveredBytes, 9, '应覆盖 9 个字节（位置 9 缺失）');
  assert.strictEqual(d.gapBytes, 1, '缺口 1 字节');
  assert.strictEqual(d.gaps.length, 1);
  assert.deepStrictEqual([d.gaps[0].start, d.gaps[0].end], [9, 10], '缺口在展开坐标 [9,10)');
  assert.strictEqual(d.conflicts.length, 2, '位置 4、5 两个冲突字节');

  // 展示保留“文件中先捕获”的字节；冲突证据列出双方。
  assert.strictEqual(d.conflicts[0].pos, 4);
  assert.strictEqual(d.conflicts[0].keptByte, 'D'.charCodeAt(0), '位置4 先捕获者是包3的 D');
  assert.strictEqual(d.conflicts[0].packets[1].byte, 0x58);
  assert.strictEqual(d.conflicts[1].pos, 5);
  assert.strictEqual(d.conflicts[1].keptByte, 'E'.charCodeAt(0), '位置5 先捕获者是包2的 E');
  assert.strictEqual(d.conflicts[1].packets[1].byte, 0x58);

  // 两个覆盖 run：[1..9] = ABCDEFGH，[10..11] = J；缺口两侧不得拼成 ...HJ
  const assembled = runBytes(model, 0, 'AtoB');
  assert.deepStrictEqual(assembled.slice(0, 8), full.slice(0, 8));
  assert.strictEqual(assembled.length, 9);
  assert.strictEqual(assembled[8], 'J'.charCodeAt(0));
  assert.ok(runText(model, 0, 'AtoB').includes('[缺口 1 字节]'), '文本必须显式标注缺口');

  // 重传统计：包5（pktIndex=4）4 字节全为相同重叠；包4（pktIndex=3）2 字节冲突
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 4).retransmitBytes, 4);
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).conflictBytes, 2);
});

test('32 位序号回绕边界：...fffffffe 之后连续拼接到 00000000', () => {
  tsCounter = 2000000;
  const payload = Buffer.from('WRAP_DATA_0123456789'); // 21 字节
  const ISN = 0xfffffffe;
  // 数据 seq 从 0xffffffff 开始（ISN+1），发 5 字节；回绕后 seq=4 发剩余 16 字节。
  const recs = [
    tcpPkt({ seq: ISN, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0xffffffff, payload: payload.slice(0, 5) }),
    tcpPkt({ seq: 4, payload: payload.slice(5) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.gaps.length, 0, '回绕处连续，不应有缺口');
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.coveredBytes, payload.length);
  assert.deepStrictEqual(runBytes(model, 0, 'AtoB'), payload, '回绕后内容必须无缝拼接');
});

test('回绕之后仍有缺口：显式留空且不拼接', () => {
  tsCounter = 3000000;
  // anchor SYN=fffffffe（位置0）。
  // seq=ffffffff,5B 'ABCDE' 覆盖位置1..6？不：5 字节占 seq ff,00,01,02,03 => 位置1..6(end=6)。
  // seq=5,1B 'G' 展开位置 7 => 缺位置6（seq=4），恰好 1 字节，缺口跨在回绕点之后。
  const recs = [
    tcpPkt({ seq: 0xfffffffe, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0xffffffff, payload: Buffer.from('ABCDE') }),
    tcpPkt({ seq: 5, payload: Buffer.from('G') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.gaps.length, 1);
  assert.deepStrictEqual([d.gaps[0].start, d.gaps[0].end], [6, 7], '位置 6（seq=4）缺失');
  assert.deepStrictEqual(runBytes(model, 0, 'AtoB'), Buffer.from('ABCDEG'));
  assert.ok(runText(model, 0, 'AtoB').includes('[缺口 1 字节]'));
});

test('无 SYN 时以首个数据段 seq 为锚点，不乱报前置缺口', () => {
  tsCounter = 4000000;
  const recs = [
    tcpPkt({ seq: 0x77777770, payload: Buffer.from('hello') }),
    tcpPkt({ seq: 0x77777775, payload: Buffer.from(' world') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.isnRaw, null);
  assert.strictEqual(d.gaps.length, 0);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'hello world');
  assert.strictEqual(d.packets[0].relSeq, 0);
});

test('双向四元组归并与方向归一化', () => {
  tsCounter = 5000000;
  const recs = [
    tcpPkt({ seq: 100, flags: FLAGS.SYN, srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80 }),
    tcpPkt({ seq: 500, flags: FLAGS.SYN, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111 }),
    tcpPkt({ seq: 101, payload: Buffer.from('req'), srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80 }),
    tcpPkt({ seq: 501, payload: Buffer.from('resp'), srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111 })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 1);
  const conn = model.connections[0];
  // IP 字典序归一化：10.0.0.1 为 A
  assert.strictEqual(conn.endpointA.key, '10.0.0.1:1111');
  assert.strictEqual(conn.endpointB.key, '10.0.0.2:80');
  assert.strictEqual(conn.directionAtoB.text, 'req');
  assert.strictEqual(conn.directionBtoA.text, 'resp');
  assert.strictEqual(conn.directionAtoB.isnRaw, 100);
  assert.strictEqual(conn.directionBtoA.isnRaw, 500);
});

test('冻结快照与工作缓冲隔离：深拷贝，后续解析不影响已冻结对象', () => {
  tsCounter = 6000000;
  const buf1 = buildPcap([
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('FIRST') })
  ]);
  const r1 = buildFromBuf(buf1);
  const snap = ReassemblyLib.freezeModel(r1.model, { fileName: 'a.pcap' });
  assert.strictEqual(snap.model.connections[0].directionAtoB.runs[0].bytes[0], 'F'.charCodeAt(0));
  // 冻结对象是普通数组深拷贝，与 Uint8Array 工作缓冲无共享
  assert.ok(Array.isArray(snap.model.connections[0].directionAtoB.runs[0].bytes));
  assert.strictEqual(snap.meta.fileName, 'a.pcap');
  assert.ok(snap.snapshotId);

  // 再解析第二份文件，快照不变
  const buf2 = buildPcap([
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('SECOND_FILE') })
  ]);
  buildFromBuf(buf2);
  assert.strictEqual(
    Buffer.from(snap.model.connections[0].directionAtoB.runs[0].bytes).toString(),
    'FIRST'
  );
});

test('错误魔数 / 大端 / pcapng：整份拒绝', () => {
  const badMagic = Buffer.from(GLOBAL_HEADER);
  badMagic.writeUInt32LE(0x12345678, 0);
  assert.throws(() => parseBuf(badMagic), /魔数/);

  const bigEndian = Buffer.from(GLOBAL_HEADER);
  bigEndian[0] = 0xa1; bigEndian[1] = 0xb2; bigEndian[2] = 0xc3; bigEndian[3] = 0xd4;
  assert.throws(() => parseBuf(bigEndian), /大端/);

  const pcapng = Buffer.from(GLOBAL_HEADER);
  pcapng[0] = 0x4d; pcapng[1] = 0x3c; pcapng[2] = 0xb2; pcapng[3] = 0xa1;
  assert.throws(() => parseBuf(pcapng), /pcapng/);

  assert.throws(() => parseBuf(Buffer.alloc(10)), /全局文件头/);
});

test('非以太网链路层：整份拒绝', () => {
  const gh = Buffer.from(GLOBAL_HEADER);
  gh.writeUInt16LE(12, 20); // LINKTYPE_RAW
  assert.throws(() => parseBuf(buildPcap([], { globalHeader: gh })), /链路层/);
});

test('单个截断包：保留文件偏移证据并停止，此前包仍可见', () => {
  tsCounter = 7000000;
  const good = tcpPkt({ seq: 1, flags: FLAGS.SYN });
  const good2 = tcpPkt({ seq: 2, payload: Buffer.from('abc') });
  let truncated = buildPcap([good, good2]);

  // 情况 A：记录头被截断（文件尾只剩 10 字节）
  const cutHeader = Buffer.concat([truncated, GLOBAL_HEADER.slice(0, 10)]);
  const parsedA = parseBuf(cutHeader);
  assert.strictEqual(parsedA.packets.length, 2);
  assert.ok(parsedA.truncated);
  assert.strictEqual(parsedA.truncated.kind, 'record_header_truncated');
  assert.strictEqual(parsedA.truncated.packetIndex, 2);
  assert.strictEqual(parsedA.truncated.availableBytes, 10);
  assert.ok(parsedA.truncated.fileOffset >= 0);

  // 情况 B：记录头声称 incl_len=100，但文件只剩 5 字节数据
  const rec = pcapRecord(Buffer.from('hello world'));
  rec.writeUInt32LE(100, 8); // incl_len
  const cutData = Buffer.concat([truncated, rec.slice(0, 16 + 5)]);
  const parsedB = parseBuf(cutData);
  assert.strictEqual(parsedB.packets.length, 2);
  assert.strictEqual(parsedB.truncated.kind, 'record_data_truncated');
  assert.strictEqual(parsedB.truncated.inclLen, 100);
  assert.strictEqual(parsedB.truncated.availableBytes, 5);
});

test('2000 包上限：第 2001 个包停止并给出证据', () => {
  tsCounter = 8000000;
  const recs = [];
  for (let i = 0; i < 2005; i++) recs.push(tcpPkt({ seq: i, payload: Buffer.from([65 + (i % 26)]) }));
  const parsed = parseBuf(buildPcap(recs));
  assert.strictEqual(parsed.packets.length, 2000);
  assert.strictEqual(parsed.truncated.kind, 'packet_limit');
  assert.strictEqual(parsed.truncated.packetIndex, 2000);
});

test('非 IPv4 EtherType / 非 TCP 协议：列入“未纳入重组”，TCP 连接不受影响', () => {
  tsCounter = 9000000;
  const recs = [
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('ok') }),
    tcpPkt({ ethertype: 0x0806 }), // ARP
    tcpPkt({ protocol: 17, payload: Buffer.from('udp-ish') }) // UDP
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 1);
  assert.strictEqual(model.unclassifiedCount, 2);
  assert.strictEqual(model.unclassified[0].ignored.layer, 'ethernet');
  assert.strictEqual(model.unclassified[1].ignored.layer, 'ipv4');
  assert.strictEqual(runText(model, 0, 'AtoB'), 'ok');
});

test('snaplen 截断（origLen > inclLen）：标记但不当作文件损坏', () => {
  tsCounter = 9500000;
  const longPayload = Buffer.alloc(100, 0x41);
  const recs = [
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: longPayload, inclLen: 40 }) // 帧截到 40：14 eth + 20 ip + 6 字节 TCP
  ];
  const parsed = parseBuf(buildPcap(recs));
  assert.strictEqual(parsed.truncated, null, 'snaplen 截断不是文件截断');
  const pkt = parsed.packets[1];
  assert.strictEqual(pkt.snapTruncated, true);
  assert.ok(pkt.ignored);
  assert.match(pkt.ignored.reason, /TCP/);
});

test('重叠冲突时“文件先捕获者胜”，与 IP 标识顺序无关地对拍确认', () => {
  tsCounter = 9800000;
  // 同一个位置，先抓到字节 Z（乱序后到的数据段先写入文件），再抓到真正的 A
  const recs = [
    tcpPkt({ seq: 1000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 1005, payload: Buffer.from([0x5a]) }), // 文件先捕获：位置 5 = 'Z'
    tcpPkt({ seq: 1001, payload: Buffer.from('ABCDEFG') }) // 文件后捕获：位置 5 应为 'F'
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 1);
  // 位置5 对应 'ABCDEFG' 索引4 = 'E'(69)；先捕获的 Z(90) 被保留
  assert.strictEqual(d.conflicts[0].keptByte, 0x5a, '保留文件先捕获的 Z');
  assert.strictEqual(d.conflicts[0].packets[1].byte, 'E'.charCodeAt(0));
  // pktIndex 为全局包号：SYN=#1(index0)、Z 段=#2(index1)、ABCDEFG=#3(index2)
  assert.strictEqual(d.conflicts[0].ownerPkt, 1);
  assert.strictEqual(d.conflicts[0].packets[0].pktIndex, 1);
  assert.strictEqual(d.conflicts[0].packets[1].pktIndex, 2);
  const bytes = runBytes(model, 0, 'AtoB');
  assert.strictEqual(bytes.toString(), 'ABCDZFG', '展示流使用先捕获字节，不按到达顺序覆盖');
});

test('连续多字节冲突：逐位置独立标记，先捕获者全部保留', () => {
  tsCounter = 9600000;
  const recs = [
    tcpPkt({ seq: 100, flags: FLAGS.SYN }),
    tcpPkt({ seq: 101, payload: Buffer.from('ZZZZZZ') }), // 文件先捕获 6 个 Z
    tcpPkt({ seq: 101, payload: Buffer.from('ABCDEF') })  // 后到 6 个不同字节
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 6);
  assert.deepStrictEqual(d.conflicts.map((c) => c.keptByte), Array.from(Buffer.from('ZZZZZZ')));
  assert.deepStrictEqual(d.conflicts.map((c) => c.packets[1].byte), Array.from(Buffer.from('ABCDEF')));
  assert.strictEqual(runText(model, 0, 'AtoB'), 'ZZZZZZ');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 2).conflictBytes, 6);
  assert.strictEqual(d.gaps.length, 0);
});

test('多字节相同重传（乱序后整段重复）：全部去重、无冲突、无缺口', () => {
  tsCounter = 9650000;
  const recs = [
    tcpPkt({ seq: 5000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 5006, payload: Buffer.from('worLD!') }), // 乱序中段先到
    tcpPkt({ seq: 5001, payload: Buffer.from('hello') }), // 首段后到
    tcpPkt({ seq: 5001, payload: Buffer.from('hello') }), // 完全相同重传
    tcpPkt({ seq: 5006, payload: Buffer.from('worLD!') }) // 完全相同重传
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.gaps.length, 0);
  assert.strictEqual(d.coveredBytes, 11);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'helloworLD!');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).retransmitBytes, 5, '第4个包 hello 完全重传');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 4).retransmitBytes, 6, '第5个包 worLD! 完全重传');
});

test('回绕边界附近乱序重叠：重复字节去重，不产生伪造缺口', () => {
  tsCounter = 9700000;
  // SYN ffffffd=位置0；段X fffffffe,4B 'abcd' 覆盖 seq fe,ff,00,01（位置1..5，跨回绕）；
  // 段Y seq=2,4B 'stuv' 覆盖位置5..9。乱序：Y 先到、X 后到，二者在 seq=1/2 边界相邻不重叠。
  const recs = [
    tcpPkt({ seq: 0xfffffffd, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0x00000002, payload: Buffer.from('stuv') }), // 回绕后段先到
    tcpPkt({ seq: 0xfffffffe, payload: Buffer.from('abcd') }), // 回绕前段后到
    tcpPkt({ seq: 0x00000002, payload: Buffer.from('stuv') }) // 完全相同重传
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.gaps.length, 0, '回绕两侧乱序到达后仍应无缝');
  assert.strictEqual(d.coveredBytes, 8);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'abcdstuv');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).retransmitBytes, 4);
});

test('IP 分片（MF / 偏移）不参与重组', () => {
  tsCounter = 9900000;
  const tcp = buildTcp({ seq: 2, flags: FLAGS.ACK, payload: Buffer.from('xx'), srcPort: 1, dstPort: 2 });
  let ip = buildIpv4({ srcIp: '1.1.1.1', dstIp: '2.2.2.2', payload: tcp });
  ip.writeUInt16BE(0x2000, 6); // MF=1
  const frame = buildEther({ payload: ip });
  const recs = [tcpPkt({ seq: 1, flags: FLAGS.SYN, srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 1, dstPort: 2 }), pcapRecord(frame)];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.unclassifiedCount, 1);
  assert.match(model.unclassified[0].ignored.reason, /分片/);
});

// ---------------- 同四元组多会话拆分 ----------------

// 客户端 10.0.0.1:1111 -> 服务端 10.0.0.2:80 的便捷构造
function cPkt(o) {
  return tcpPkt(Object.assign({ srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80 }, o));
}
function sPkt(o) {
  return tcpPkt(Object.assign({ srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111 }, o));
}

test('同四元组两次会话（FIN 正常关闭 + 新 SYN）：拆分，第二会话不计重传/冲突/缺口', () => {
  tsCounter = 10000000;
  const recs = [
    // 会话 1：ISN_C=1000 / ISN_S=9000，双向 FIN 正常关闭
    cPkt({ seq: 1000, flags: FLAGS.SYN }),
    sPkt({ seq: 9000, ack: 1001, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 1001, ack: 9001, payload: Buffer.from('HELLO-1') }),
    sPkt({ seq: 9001, ack: 1008, payload: Buffer.from('RSP1') }),
    cPkt({ seq: 1008, ack: 9005, flags: FLAGS.FIN | FLAGS.ACK }),
    sPkt({ seq: 9005, ack: 1009, flags: FLAGS.FIN | FLAGS.ACK }),
    cPkt({ seq: 1009, ack: 9006, flags: FLAGS.ACK }),
    // 会话 2：同四元组，全新 ISN
    cPkt({ seq: 0x20000000, flags: FLAGS.SYN }),
    sPkt({ seq: 0x60000000, ack: 0x20000001, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 0x20000001, ack: 0x60000001, payload: Buffer.from('HELLO-2') }),
    sPkt({ seq: 0x60000001, ack: 0x20000008, payload: Buffer.from('RSP2') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2, '两次会话必须拆成两条连接');

  const [c1, c2] = model.connections;
  assert.strictEqual(c1.tupleKey, '10.0.0.1:1111<->10.0.0.2:80');
  assert.strictEqual(c1.sessionIndex, 1);
  assert.strictEqual(c1.tupleSessionCount, 2);
  assert.strictEqual(c2.sessionIndex, 2);
  assert.strictEqual(c2.splitReason.type, 'syn_new_isn');
  assert.match(c2.splitReason.message, /包 #8/);

  // 各自方向独立重组：文本、缺口、冲突互不污染
  assert.strictEqual(c1.directionAtoB.text, 'HELLO-1');
  assert.strictEqual(c1.directionBtoA.text, 'RSP1');
  assert.strictEqual(c2.directionAtoB.text, 'HELLO-2');
  assert.strictEqual(c2.directionBtoA.text, 'RSP2');
  for (const c of [c1, c2]) {
    for (const d of [c.directionAtoB, c.directionBtoA]) {
      assert.strictEqual(d.gaps.length, 0);
      assert.strictEqual(d.conflicts.length, 0);
      assert.ok(d.packets.every((p) => p.retransmitBytes === 0), '第二会话的字节不得计为重传');
    }
  }

  // 包归属一致性：每个 TCP 包恰好属于一个会话
  assert.strictEqual(c1.packetCount, 7);
  assert.strictEqual(c2.packetCount, 4);
  assert.strictEqual(c1.packetCount + c2.packetCount, model.packetTotal);
  assert.deepStrictEqual(
    c2.directionAtoB.packets.map((p) => p.pktIndex),
    [7, 9],
    '第二会话 A→B 只含自己的 SYN 与数据包'
  );
  assert.strictEqual(c1.directionAtoB.isnRaw, 1000);
  assert.strictEqual(c2.directionAtoB.isnRaw, 0x20000000);
});

test('同四元组两次会话（RST 异常复位关闭）：第二会话 SYN 拆分', () => {
  tsCounter = 10100000;
  const recs = [
    cPkt({ seq: 500, flags: FLAGS.SYN }),
    sPkt({ seq: 8000, ack: 501, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 501, ack: 8001, payload: Buffer.from('FIRST') }),
    cPkt({ seq: 506, ack: 8001, flags: FLAGS.RST | FLAGS.ACK }), // 异常复位
    cPkt({ seq: 0x40000000, flags: FLAGS.SYN }), // 第二会话
    sPkt({ seq: 0x70000000, ack: 0x40000001, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 0x40000001, ack: 0x70000001, payload: Buffer.from('SECOND') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'FIRST');
  assert.strictEqual(model.connections[1].directionAtoB.text, 'SECOND');
  assert.strictEqual(model.connections[1].splitReason.type, 'syn_new_isn');
  assert.strictEqual(model.connections[0].packetCount + model.connections[1].packetCount, model.packetTotal);
});

test('缺少握手包（抓包从数据开始）：第二会话 SYN 仍触发拆分', () => {
  tsCounter = 10200000;
  const recs = [
    // 会话 1 的握手未抓到，只有数据与 FIN
    cPkt({ seq: 5000, ack: 1, payload: Buffer.from('AAA') }),
    cPkt({ seq: 5003, ack: 1, flags: FLAGS.FIN | FLAGS.ACK }),
    // 会话 2 的握手完整
    cPkt({ seq: 0x11111111, flags: FLAGS.SYN }),
    cPkt({ seq: 0x11111112, ack: 1, payload: Buffer.from('BBB') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.directionAtoB.isnRaw, null, '第一会话未见 SYN');
  assert.strictEqual(c1.directionAtoB.text, 'AAA');
  assert.strictEqual(c2.directionAtoB.text, 'BBB');
  assert.strictEqual(c2.directionAtoB.isnRaw, 0x11111111);
  assert.strictEqual(c1.packetCount + c2.packetCount, model.packetTotal);
});

test('两次会话握手都缺失：FIN 关闭 + 序号不属于旧会话空间 => 拆分', () => {
  tsCounter = 10300000;
  const recs = [
    // 会话 1：无握手，数据 + 双向 FIN
    cPkt({ seq: 1000, ack: 2001, payload: Buffer.from('AAAA') }),
    sPkt({ seq: 2000, ack: 1004, payload: Buffer.from('aaaa') }),
    cPkt({ seq: 1004, ack: 2005, flags: FLAGS.FIN | FLAGS.ACK }),
    sPkt({ seq: 2005, ack: 1005, flags: FLAGS.FIN | FLAGS.ACK }),
    // 会话 2：握手同样缺失，全新序号空间
    cPkt({ seq: 0x50000000, ack: 0x60000001, payload: Buffer.from('BBBB') }),
    sPkt({ seq: 0x60000000, ack: 0x50000004, payload: Buffer.from('bbbb') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.directionAtoB.text, 'AAAA');
  assert.strictEqual(c1.directionBtoA.text, 'aaaa');
  assert.strictEqual(c2.directionAtoB.text, 'BBBB');
  assert.strictEqual(c2.directionBtoA.text, 'bbbb');
  assert.strictEqual(c2.splitReason.type, 'after_close');
  assert.match(c2.splitReason.message, /关闭/);
  assert.strictEqual(c1.packetCount + c2.packetCount, model.packetTotal);
});

test('单向片段（只抓到 A→B）：RST 关闭后新数据拆分；FIN 后越过 FIN 的数据拆分', () => {
  tsCounter = 10400000;
  // 情形 1：单向 + RST 关闭
  let recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    cPkt({ seq: 101, ack: 1, payload: Buffer.from('ONE') }),
    cPkt({ seq: 104, ack: 1, flags: FLAGS.RST | FLAGS.ACK }),
    cPkt({ seq: 0x90000000, ack: 1, payload: Buffer.from('TWO') }) // 新会话 SYN 漏抓
  ];
  let { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'ONE');
  assert.strictEqual(model.connections[1].directionAtoB.text, 'TWO');
  assert.strictEqual(model.connections[1].splitReason.type, 'after_close');
  assert.strictEqual(model.connections[1].directionBtoA.packetCount, 0, '单向片段对向无包');

  // 情形 2：单向 + FIN，之后同方向出现越过 FIN 序号位的数据（同一连接不可能）
  tsCounter = 10450000;
  recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    cPkt({ seq: 101, ack: 1, payload: Buffer.from('ONE') }),
    cPkt({ seq: 104, ack: 1, flags: FLAGS.FIN | FLAGS.ACK }), // FIN 占序号位 4
    cPkt({ seq: 200, ack: 1, payload: Buffer.from('TWO') }) // 展开坐标 99..102，越过 FIN
  ];
  ({ model } = buildFromBuf(buildPcap(recs)));
  assert.strictEqual(model.connections.length, 2);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'ONE');
  assert.strictEqual(model.connections[1].directionAtoB.text, 'TWO');
  assert.strictEqual(model.connections[1].splitReason.type, 'data_after_fin');
});

test('数据序号落在本方向 ISN 之前（同一连接不可能）=> 拆分', () => {
  tsCounter = 10500000;
  const recs = [
    cPkt({ seq: 1000, flags: FLAGS.SYN }),
    cPkt({ seq: 1001, ack: 1, payload: Buffer.from('AAAA') }),
    cPkt({ seq: 500, ack: 1, payload: Buffer.from('BB') }) // 新会话数据（SYN 漏抓），seq 在 ISN 之前
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'AAAA');
  assert.strictEqual(model.connections[1].directionAtoB.text, 'BB');
  assert.strictEqual(model.connections[1].splitReason.type, 'seq_before_isn');
});

test('序号回绕 + 四元组复用：回绕不触发误拆分，两会话各自正确重组', () => {
  tsCounter = 10600000;
  const recs = [
    // 会话 1：ISN 紧贴回绕点，数据跨 0xffffffff
    cPkt({ seq: 0xfffffffe, flags: FLAGS.SYN }),
    cPkt({ seq: 0xffffffff, ack: 1, payload: Buffer.from('ABCDE') }), // 占 seq ff..03
    cPkt({ seq: 4, ack: 1, flags: FLAGS.FIN | FLAGS.ACK }),
    sPkt({ seq: 8000, ack: 5, flags: FLAGS.FIN | FLAGS.ACK }), // 对向 FIN 使会话关闭
    // 会话 2：同四元组新 ISN
    cPkt({ seq: 0x00000010, flags: FLAGS.SYN }),
    cPkt({ seq: 0x00000011, ack: 8001, payload: Buffer.from('XY') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2, '回绕不得误拆、复用必须拆');
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.directionAtoB.text, 'ABCDE');
  assert.strictEqual(c1.directionAtoB.gaps.length, 0, '回绕处无缝');
  assert.strictEqual(c2.directionAtoB.text, 'XY');
  assert.strictEqual(c2.splitReason.type, 'syn_new_isn');
});

test('两次会话之间夹杂其他连接：拆分状态按四元组隔离', () => {
  tsCounter = 10700000;
  const recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    cPkt({ seq: 101, ack: 1, payload: Buffer.from('X1') }),
    // 另一个四元组的完整连接插在中间
    tcpPkt({ seq: 777, flags: FLAGS.SYN, srcIp: '10.0.0.3', srcPort: 2000, dstIp: '10.0.0.4', dstPort: 3000 }),
    tcpPkt({ seq: 778, ack: 1, payload: Buffer.from('YY'), srcIp: '10.0.0.3', srcPort: 2000, dstIp: '10.0.0.4', dstPort: 3000 }),
    // 原四元组的第二会话
    cPkt({ seq: 0x50000000, flags: FLAGS.SYN }),
    cPkt({ seq: 0x50000001, ack: 1, payload: Buffer.from('X2') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 3, 'X 两会话 + Y 一会话');
  const [x1, y, x2] = model.connections; // 按首包序号排序
  assert.strictEqual(x1.directionAtoB.text, 'X1');
  assert.strictEqual(y.directionAtoB.text, 'YY');
  assert.strictEqual(y.tupleSessionCount, 1, '夹杂连接不受影响');
  assert.strictEqual(x2.directionAtoB.text, 'X2');
  assert.strictEqual(x2.splitReason.type, 'syn_new_isn');
  assert.strictEqual(
    model.connections.reduce((n, c) => n + c.packetCount, 0),
    model.packetTotal,
    '每个 TCP 包恰好归属一个会话'
  );
});

test('第二会话期间迟到的第一会话重传/控制包：归回来源会话，不污染新会话证据', () => {
  tsCounter = 10800000;
  const recs = [
    cPkt({ seq: 1000, flags: FLAGS.SYN }),
    cPkt({ seq: 1001, ack: 1, payload: Buffer.from('ABCDEF') }),
    // 第二会话开始（第一会话未见关闭）
    cPkt({ seq: 0x20000000, flags: FLAGS.SYN }),
    cPkt({ seq: 0x20000001, ack: 1, payload: Buffer.from('XYZ') }),
    // 迟到的第一会话重传（相同字节）与迟到的第一会话 FIN
    cPkt({ seq: 1001, ack: 1, payload: Buffer.from('ABCDEF') }),
    cPkt({ seq: 1007, ack: 1, flags: FLAGS.FIN | FLAGS.ACK })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.packetCount, 4, '迟到的重传与 FIN 归回第一会话');
  assert.strictEqual(c2.packetCount, 2);
  assert.strictEqual(c1.directionAtoB.text, 'ABCDEF');
  assert.strictEqual(c2.directionAtoB.text, 'XYZ');
  // 重传统计记在来源会话；新会话无冲突、无缺口、无重传
  assert.strictEqual(c1.directionAtoB.packets.find((p) => p.pktIndex === 4).retransmitBytes, 6);
  assert.strictEqual(c2.directionAtoB.conflicts.length, 0);
  assert.strictEqual(c2.directionAtoB.gaps.length, 0);
  assert.ok(c2.directionAtoB.packets.every((p) => p.retransmitBytes === 0));
  // 迟到的 FIN 归回第一会话后，第一会话方向状态一致（FIN 被记录）
  assert.strictEqual(c1.directionAtoB.finSeq, 1007);
});

test('SYN 重传（同 ISN）与同时打开的双向 SYN：均不拆分', () => {
  tsCounter = 10900000;
  const recs = [
    cPkt({ seq: 500, flags: FLAGS.SYN }),
    cPkt({ seq: 500, flags: FLAGS.SYN }), // 同 ISN 重传
    sPkt({ seq: 900, ack: 501, flags: FLAGS.SYN | FLAGS.ACK }),
    sPkt({ seq: 900, ack: 501, flags: FLAGS.SYN | FLAGS.ACK }), // SYN+ACK 重传
    cPkt({ seq: 501, ack: 901, payload: Buffer.from('ok') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 1);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'ok');
  assert.strictEqual(model.connections[0].packetCount, 5);
});

test('半关闭：单方向 FIN 后对向继续传数据，不拆分；双向 FIN 后新 SYN 才拆分', () => {
  tsCounter = 11000000;
  const recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    sPkt({ seq: 9000, ack: 101, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 101, ack: 9001, flags: FLAGS.FIN | FLAGS.ACK }), // A→B 方向关闭
    sPkt({ seq: 9001, ack: 102, payload: Buffer.from('still-sending') }), // 半关闭：对向继续
    sPkt({ seq: 9014, ack: 102, flags: FLAGS.FIN | FLAGS.ACK }), // 对向也关闭
    cPkt({ seq: 0x30000000, flags: FLAGS.SYN }) // 新会话
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.directionBtoA.text, 'still-sending', '半关闭数据属于同一会话');
  assert.strictEqual(c1.packetCount, 5);
  assert.strictEqual(c2.packetCount, 1);
});

test('第二会话 SYN 漏抓但其 SYN+ACK 被捕获：新 ISN 的 SYN+ACK 触发拆分', () => {
  tsCounter = 11100000;
  const recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    sPkt({ seq: 900, ack: 101, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 101, ack: 901, payload: Buffer.from('A1') }),
    cPkt({ seq: 103, ack: 901, flags: FLAGS.FIN | FLAGS.ACK }),
    sPkt({ seq: 901, ack: 104, flags: FLAGS.FIN | FLAGS.ACK }),
    // 第二会话的 SYN 漏抓，SYN+ACK 带着新 ISN 出现
    sPkt({ seq: 0x80000000, ack: 0x12345678, flags: FLAGS.SYN | FLAGS.ACK }),
    sPkt({ seq: 0x80000001, ack: 0x12345678, payload: Buffer.from('B2') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const [c1, c2] = model.connections;
  assert.strictEqual(c1.directionAtoB.text, 'A1');
  assert.strictEqual(c2.directionBtoA.text, 'B2');
  assert.strictEqual(c2.splitReason.type, 'synack_new_isn');
  assert.strictEqual(c2.directionBtoA.isnRaw, 0x80000000);
});

test('同四元组三次会话 + 失败连接尝试（仅 SYN）：各自独立归属', () => {
  tsCounter = 11200000;
  const recs = [
    cPkt({ seq: 100, flags: FLAGS.SYN }),
    cPkt({ seq: 101, ack: 1, payload: Buffer.from('S1') }),
    cPkt({ seq: 103, ack: 1, flags: FLAGS.RST | FLAGS.ACK }), // 会话 1 复位
    cPkt({ seq: 0x40000000, flags: FLAGS.SYN }), // 失败尝试：只有 SYN，无应答
    cPkt({ seq: 0x50000000, flags: FLAGS.SYN }), // 换了新 ISN 重试 => 另一会话
    cPkt({ seq: 0x50000001, ack: 1, payload: Buffer.from('S3') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 3);
  assert.strictEqual(model.connections[0].directionAtoB.text, 'S1');
  assert.strictEqual(model.connections[1].packetCount, 1, '失败尝试仅含自己的 SYN');
  assert.strictEqual(model.connections[1].directionAtoB.isnRaw, 0x40000000);
  assert.strictEqual(model.connections[2].directionAtoB.text, 'S3');
  assert.strictEqual(model.connections[2].directionAtoB.isnRaw, 0x50000000);
});

// ---------------- 限定版 HTTP/1.1 报文识别 ----------------

function httpDir(model, connIndex, dir) {
  const conn = model.connections[connIndex];
  return dir === 'AtoB' ? conn.directionAtoB.http : conn.directionBtoA.http;
}

/** 构造一条完整方向流的客户端请求（默认无握手，首段 seq=1000）。 */
function httpStream(segments, { seq = 1000, srcIp = '10.0.0.1', dstIp = '10.0.0.2', srcPort = 1111, dstPort = 80 } = {}) {
  const recs = [];
  let s = seq;
  for (const p of segments) {
    const buf = Buffer.isBuffer(p) ? p : p.payload;
    const opts = Buffer.isBuffer(p) ? {} : p;
    recs.push(tcpPkt(Object.assign({
      seq: s, payload: buf, srcIp, dstIp, srcPort, dstPort
    }, opts)));
    s += buf.length;
  }
  return buildPcap(recs);
}

function oneDir(buf, splitAt) {
  // 单方向、连续、无缺口：可把完整报文拆到多个包（跨包头部）
  const segs = [];
  if (splitAt) {
    let o = 0;
    for (const cut of splitAt) { segs.push(buf.slice(o, cut)); o = cut; }
    segs.push(buf.slice(o));
  } else {
    segs.push(buf);
  }
  return buildFromBuf(httpStream(segs));
}

test('HTTP：完整请求无消息体（仅头部），区间与包号证据正确', () => {
  tsCounter = 20000000;
  const req = Buffer.from('GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n');
  const { model } = oneDir(req);
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  const m = h.messages[0];
  assert.strictEqual(m.status, 'complete');
  assert.strictEqual(m.kind, 'request');
  assert.strictEqual(m.startLine.method, 'GET');
  assert.strictEqual(m.startLine.target, '/index.html');
  assert.strictEqual(m.bodyLengthExpected, 0);
  assert.strictEqual(m.relStart, 0, '无 SYN 时锚点为首个数据段 seq，首字节展开坐标为 0');
  assert.strictEqual(m.relEnd, req.length);
  assert.strictEqual(m.presentBytes, req.length);
  assert.deepStrictEqual(m.evidence.packets.map((p) => p.pktNumber), [1]);
});

test('HTTP：跨包起始行与头部（在任意边界拆包），仍是同一连续字节上的完整报文', () => {
  tsCounter = 20100000;
  const req = Buffer.from('POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world');
  // 起始行中间、CRLF 中间、头部中间、空行中间、消息体中间都切开
  const { model } = oneDir(req, [4, 5, 12, 30, 41, 45, 55, 57]);
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  const m = h.messages[0];
  assert.strictEqual(m.status, 'complete', '跨包不影响完整性：' + (m.reason || ''));
  assert.strictEqual(m.bodyLengthPresent, 11);
  // 证据段覆盖全部 9 个包，首尾区间拼起来等于整个报文区间
  const spans = m.evidence.packets;
  assert.ok(spans.length >= 2, '跨多个包');
  assert.deepStrictEqual([spans[0].start, spans[spans.length - 1].end], [m.start, m.end]);
  let total = 0;
  for (let i = 0; i < spans.length; i++) {
    assert.strictEqual(spans[i].end - spans[i].start, spans[i].bytes);
    if (i > 0) assert.strictEqual(spans[i].start, spans[i - 1].end, '证据段必须首尾相接无重叠');
    total += spans[i].bytes;
  }
  assert.strictEqual(total, req.length);
});

test('HTTP：相同字节重传不改变报文；重传包号作为旁证列出', () => {
  tsCounter = 20200000;
  const req = Buffer.from('GET /r HTTP/1.1\r\n\r\n');
  const recs = [
    tcpPkt({ seq: 1000, payload: req.slice(0, 10) }),
    tcpPkt({ seq: 1010, payload: req.slice(10) }),
    tcpPkt({ seq: 1000, payload: req.slice(0, 10) }), // 完全相同重传
    tcpPkt({ seq: 1010, payload: req.slice(10) }) // 完全相同重传
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  assert.strictEqual(h.messages[0].status, 'complete');
  // 归属证据只含首见包 #1、#2；旁证含重传包 #3、#4
  assert.deepStrictEqual(h.messages[0].evidence.packets.map((p) => p.pktNumber), [1, 2]);
  assert.deepStrictEqual(h.messages[0].evidence.retransmitPackets, [2, 3]);
});

test('HTTP：头部区域存在字节冲突 => 语法再完整也标未完成', () => {
  tsCounter = 20300000;
  const req = Buffer.from('GET /c HTTP/1.1\r\n\r\n');
  const evil = Buffer.from(req); evil[8] = 0x58; // 位置 1008 -> 展开 8
  const recs = [
    tcpPkt({ seq: 1000, payload: req }), // 正确字节先捕获（首见保留）
    tcpPkt({ seq: 1008, payload: evil.slice(8, 9) }) // 冲突字节后到
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  const m = h.messages[0];
  assert.strictEqual(m.status, 'incomplete');
  assert.strictEqual(m.reasonCode, 'conflict_in_message');
  assert.ok(m.conflicts.length >= 1);
  assert.strictEqual(m.conflicts[0].ownerPkt, 0, '先捕获的正确字节保留（pktIndex 从 0 起）');
});

test('HTTP：消息体区域存在字节冲突 => 同样标未完成（不输出伪完整报文）', () => {
  tsCounter = 20350000;
  const req = Buffer.from('POST /b HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc');
  const evil = Buffer.from(req); evil[evil.length - 2] = 0x5a; // 正文 'b'->'Z'
  const recs = [
    tcpPkt({ seq: 1000 + evil.length - 3, payload: evil.slice(evil.length - 3, evil.length - 1) }), // 正文前两字节先到（含 Z）
    tcpPkt({ seq: 1000, payload: req }) // 完整正确后到 => 仅正文位置冲突
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  const m = h.messages[0];
  assert.strictEqual(m.status, 'incomplete');
  assert.strictEqual(m.reasonCode, 'conflict_in_message');
});

test('HTTP：头部块中间有缺口 => 不拼接缺口两侧文本，候选标未完成', () => {
  tsCounter = 20400000;
  // GET /g HTTP/1.1\r\nX-A: 1\r\n\r\n —— 故意丢掉中间 4 字节
  const full = Buffer.from('GET /g HTTP/1.1\r\nX-A: 1\r\n\r\n');
  const gapAt = 12, miss = 4;
  const recs = [
    tcpPkt({ seq: 1000, payload: full.slice(0, gapAt) }),
    tcpPkt({ seq: 1000 + gapAt + miss, payload: full.slice(gapAt + miss) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.gaps.length, 1);
  const h = d.http;
  assert.ok(h.messages.length >= 1);
  assert.ok(h.messages.every((m) => m.status !== 'complete'), '跨缺口不得产生完整报文');
  assert.ok(h.messages.some((m) => m.reasonCode === 'truncated_start_line' || m.reasonCode === 'truncated_header_block'));
});

test('HTTP：Content-Length 正文跨过缺口 => body_crosses_gap，明确不读缺口另一侧', () => {
  tsCounter = 20500000;
  const head = Buffer.from('POST /gap HTTP/1.1\r\nContent-Length: 10\r\n\r\n');
  const body = Buffer.from('0123456789');
  // 前 4 字节正文到达，缺 1 字节，后 5 字节在缺口另一侧
  const recs = [
    tcpPkt({ seq: 1000, payload: Buffer.concat([head, body.slice(0, 4)]) }),
    tcpPkt({ seq: 1000 + head.length + 5, payload: body.slice(5) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  const m = h.messages[0];
  assert.strictEqual(m.status, 'incomplete');
  assert.strictEqual(m.reasonCode, 'body_crosses_gap');
  assert.strictEqual(m.bodyLengthExpected, 10);
  assert.strictEqual(m.bodyLengthPresent, 4, '只有连续区内的 4 字节算已呈现');
  assert.ok(m.crossesGap);
  assert.strictEqual(m.gap.length, 1);
  assert.strictEqual(m.end, m.bodyStart + 4, '区间不得越过缺口包含另一侧字节');
});

test('HTTP：正文跨过缺口且缺口另一侧也有完整起始线 => 两侧分别识别，不续接', () => {
  tsCounter = 20550000;
  const head = Buffer.from('POST /gap HTTP/1.1\r\nContent-Length: 8\r\n\r\n');
  const firstBody = Buffer.from('AAAA');
  const other = Buffer.from('GET /next HTTP/1.1\r\n\r\n');
  // head+4B 后，缺口 8 字节，缺口另一侧是另一条完整请求
  const recs = [
    tcpPkt({ seq: 1000, payload: Buffer.concat([head, firstBody]) }),
    tcpPkt({ seq: 1000 + head.length + 4 + 8, payload: other })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  // 第一条：未完成跨缺口；第二条：缺口另一侧独立 run 内的完整报文
  const inc = h.messages.find((m) => m.status === 'incomplete');
  const ok = h.messages.find((m) => m.status === 'complete');
  assert.ok(inc, '前一条必须标未完成');
  assert.strictEqual(inc.reasonCode, 'body_crosses_gap');
  assert.ok(ok, '缺口另一侧的合法请求应独立识别为完整');
  assert.strictEqual(ok.startLine.target, '/next');
  assert.ok(ok.start > inc.end, '第二条区间在缺口另一侧，不与第一条拼接');
});

test('HTTP：捕获在头部块/起始线中间结束 => truncated，标未完成', () => {
  tsCounter = 20600000;
  let { model } = buildFromBuf(httpStream([Buffer.from('GET /trunc HTTP/1.1\r\nHost:')]));
  let h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages[0].status, 'incomplete');
  assert.strictEqual(h.messages[0].reasonCode, 'truncated_header_block');

  tsCounter = 20650000;
  ({ model } = buildFromBuf(httpStream([Buffer.from('GET /partial')])));
  h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages[0].status, 'incomplete');
  assert.strictEqual(h.messages[0].reasonCode, 'truncated_start_line');
});

test('HTTP：非法 Content-Length（非数字 / 多个不一致 / 逗号列表）一律未完成', () => {
  tsCounter = 20700000;
  const cases = [
    'GET /a HTTP/1.1\r\nContent-Length: abc\r\n\r\n',
    'GET /a HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n',
    'GET /a HTTP/1.1\r\nContent-Length: 1, 2\r\n\r\n'
  ];
  for (const c of cases) {
    tsCounter += 1000;
    const { model } = oneDir(Buffer.from(c));
    const m = httpDir(model, 0, 'AtoB').messages[0];
    assert.strictEqual(m.status, 'incomplete', c);
    assert.strictEqual(m.reasonCode, 'invalid_content_length', c);
  }
  // 多个取值一致的 Content-Length 仍接受（值明确）
  tsCounter += 1000;
  const { model } = oneDir(Buffer.from('GET /a HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc'));
  const m = httpDir(model, 0, 'AtoB').messages[0];
  assert.strictEqual(m.status, 'complete');
  assert.strictEqual(m.bodyLengthExpected, 3);
});

test('HTTP：Transfer-Encoding: chunked 明确标记不支持，不猜测正文边界', () => {
  tsCounter = 20800000;
  const buf = Buffer.from(
    'POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nGET /pipelined HTTP/1.1\r\n\r\n'
  );
  const { model } = oneDir(buf);
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1, 'TE 不支持，后续流水线字节不得再被识别为报文');
  const m = h.messages[0];
  assert.strictEqual(m.status, 'unsupported');
  assert.strictEqual(m.reasonCode, 'unsupported_transfer_encoding_chunked');
  assert.strictEqual(m.headerEnd, m.end, '区间到头部块结束为止，正文不纳入');
  assert.ok(h.notices.some((n) => n.type === 'unparsed_trailing'));
});

test('HTTP：非 chunked 的 Transfer-Encoding 也明确标记不支持', () => {
  tsCounter = 20850000;
  const buf = Buffer.from('GET /g HTTP/1.1\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello');
  const { model } = oneDir(buf);
  const m = httpDir(model, 0, 'AtoB').messages[0];
  assert.strictEqual(m.status, 'unsupported');
  assert.strictEqual(m.reasonCode, 'unsupported_transfer_encoding');
});

test('HTTP：响应起始线（status-line）识别，3 位状态码与原因短语', () => {
  tsCounter = 20900000;
  const resp = Buffer.from('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n');
  const recs = [
    tcpPkt({ seq: 2000, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111, payload: resp })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  // IP 字典序归一化：10.0.0.1 为 A，因此 10.0.0.2:80 发出的响应是 A→B
  const m = httpDir(model, 0, 'BtoA').messages[0];
  assert.strictEqual(m.kind, 'response');
  assert.strictEqual(m.status, 'complete');
  assert.strictEqual(m.startLine.statusCode, 404);
  assert.strictEqual(m.startLine.reasonPhrase, 'Not Found');
});

test('HTTP：非 HTTP/1.1 版本与非法起始线不识别（不编造报文）', () => {
  tsCounter = 21000000;
  let { model } = oneDir(Buffer.from('GET /old HTTP/1.0\r\n\r\n'));
  let h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 0, 'HTTP/1.0 起始线不属于限定版');
  assert.ok(h.notices.some((n) => n.type === 'unparsed_trailing'));

  tsCounter = 21050000;
  ({ model } = oneDir(Buffer.from('GARBAGE NOT HTTP AT ALL\r\n\r\n')));
  h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 0);
});

test('HTTP：run 起始前缀再同步只做一次，跳过字节留痕，中途停止不猜边界', () => {
  tsCounter = 21100000;
  // run 第一行形如 "==junk==\rGET /s HTTP/1.1"：合法起始线起始于 \r 之后，
  // 第一行内再同步定位到 GET；跳过的 "==junk==\r" 字节显式留痕。
  const junk = Buffer.from('==junk==\r');
  const req = Buffer.from('GET /s HTTP/1.1\r\n\r\n');
  const tail = Buffer.from('NOTAHTTP');
  const { model } = oneDir(Buffer.concat([junk, req, tail]));
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1);
  assert.strictEqual(h.messages[0].status, 'complete');
  assert.strictEqual(h.messages[0].start, junk.length, '报文区间不含跳过前缀（锚点 0）');
  const skip = h.notices.find((n) => n.type === 'skipped_prefix');
  assert.ok(skip);
  assert.strictEqual(skip.length, junk.length);
  assert.ok(h.notices.some((n) => n.type === 'unparsed_trailing'));
});

test('HTTP：同一连续 run 内流水线多条报文依次识别', () => {
  tsCounter = 21200000;
  const a = Buffer.from('GET /1 HTTP/1.1\r\n\r\n');
  const b = Buffer.from('POST /2 HTTP/1.1\r\nContent-Length: 2\r\n\r\nok');
  const { model } = oneDir(Buffer.concat([a, b]), [3, 20]);
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 2);
  assert.strictEqual(h.messages[0].startLine.target, '/1');
  assert.strictEqual(h.messages[1].startLine.target, '/2');
  assert.deepStrictEqual(h.messages.map((m) => m.status), ['complete', 'complete']);
  assert.strictEqual(h.messages[1].start, a.length, '第二条紧接第一条之后（锚点 0）');
});

test('HTTP：同四元组端口复用——第二会话独立识别，不续接前会话残余', () => {
  tsCounter = 21300000;
  const recs = [
    // 会话 1：只抓到一条残缺请求（CL 声称 10，正文只到 2 字节），然后 RST 关闭
    cPkt({ seq: 1000, flags: FLAGS.SYN }),
    sPkt({ seq: 9000, ack: 1001, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 1001, payload: Buffer.from('POST /one HTTP/1.1\r\nContent-Length: 10\r\n\r\nAB') }),
    cPkt({ seq: 1001 + 46, ack: 9001, flags: FLAGS.RST | FLAGS.ACK }),
    // 会话 2：同四元组新 ISN，完整请求——不得把 'AB' 当作自己的前身
    cPkt({ seq: 0x30000000, flags: FLAGS.SYN }),
    sPkt({ seq: 0x70000000, ack: 0x30000001, flags: FLAGS.SYN | FLAGS.ACK }),
    cPkt({ seq: 0x30000001, payload: Buffer.from('GET /two HTTP/1.1\r\n\r\n') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 2);
  const h1 = httpDir(model, 0, 'AtoB');
  const h2 = httpDir(model, 1, 'AtoB');
  assert.strictEqual(h1.messages.length, 1);
  assert.strictEqual(h1.messages[0].status, 'incomplete');
  assert.strictEqual(h1.messages[0].reasonCode, 'truncated_body');
  assert.strictEqual(h2.messages.length, 1);
  assert.strictEqual(h2.messages[0].status, 'complete', '第二会话不得续接前会话残余');
  assert.strictEqual(h2.messages[0].startLine.target, '/two');
  assert.deepStrictEqual(h2.messages[0].evidence.packets.map((p) => p.pktNumber), [7]);
});

test('HTTP：冻结快照内 messages 与 run 字节一致且为普通数组（同一快照）', () => {
  tsCounter = 21400000;
  const req = Buffer.from('GET /f HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc');
  const buf = httpStream([req.slice(0, 20), req.slice(20)]);
  const { model } = buildFromBuf(buf);
  const snap = ReassemblyLib.freezeModel(model, { fileName: 'h.pcap' });
  const d = snap.model.connections[0].directionAtoB;
  assert.ok(Array.isArray(d.runs[0].bytes), '冻结后字节是普通数组');
  assert.ok(Array.isArray(d.runs[0].owners), '冻结后 owner 是普通数组');
  const m = d.http.messages[0];
  assert.strictEqual(m.status, 'complete');
  // 消息区间内逐字节的归属包号必须都能在 owners 中对应到实际捕获包
  for (const span of m.evidence.packets) {
    for (let p = span.start; p < span.end; p++) {
      assert.strictEqual(d.runs[0].owners[p - d.runs[0].start], span.pktIndex);
    }
  }
  // 消息体内的字节确实可从快照 run 字节取回
  const body = d.runs[0].bytes.slice(m.bodyStart - d.runs[0].start, m.bodyEnd - d.runs[0].start);
  assert.strictEqual(Buffer.from(body).toString(), 'abc');
});

test('HTTP：Content-Length: 0 与无 CL 无 TE（按空体）均完整', () => {
  tsCounter = 21500000;
  let { model } = oneDir(Buffer.from('GET /z HTTP/1.1\r\nContent-Length: 0\r\n\r\n'));
  let m = httpDir(model, 0, 'AtoB').messages[0];
  assert.strictEqual(m.status, 'complete');
  assert.strictEqual(m.bodyLengthExpected, 0);

  tsCounter = 21550000;
  ({ model } = oneDir(Buffer.from('HTTP/1.1 204 No Content\r\nDate: x\r\n\r\n')));
  m = httpDir(model, 0, 'AtoB').messages[0];
  assert.strictEqual(m.status, 'complete');
  assert.strictEqual(m.kind, 'response');
  assert.strictEqual(m.bodyLengthExpected, 0, '无 CL 无 TE：限定版按空体，不猜连接关闭边界');
});

test('HTTP：起始线完整但头部行跨过缺口 => 标未完成，缺口另一侧不续接成同一报文', () => {
  tsCounter = 21600000;
  const a = Buffer.from('GET /h HTTP/1.1\r\nHost: exa');
  const b = Buffer.from('mple.com\r\n\r\n');
  const recs = [
    tcpPkt({ seq: 1000, payload: a }),
    tcpPkt({ seq: 1000 + a.length + 6, payload: b }) // 6 字节缺口
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  assert.strictEqual(h.messages.length, 1, '只有头部所在 run 产出候选；另一侧不合并');
  assert.strictEqual(h.messages[0].status, 'incomplete');
  assert.strictEqual(h.messages[0].reasonCode, 'truncated_header_block');
  // 缺口另一侧 run 以 'mple.com' 开头（含 CRLF 但不是合法起始线）：
  // 不产生第二条伪报文，只留“未解析”痕跡。
  assert.ok(h.notices.some((n) => n.type === 'unparsed_trailing'));
});

test('HTTP：冲突位置在报文区间之后，不影响该报文完整性', () => {
  tsCounter = 21700000;
  const req = Buffer.from('GET /o HTTP/1.1\r\n\r\n');
  const extra = Buffer.from('XXXX');
  const recs = [
    tcpPkt({ seq: 1000, payload: req }),
    tcpPkt({ seq: 1000 + req.length, payload: extra }),
    tcpPkt({ seq: 1000 + req.length, payload: Buffer.from('YYYY') }) // 与上一段冲突
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const h = httpDir(model, 0, 'AtoB');
  const complete = h.messages.find((m) => m.status === 'complete');
  assert.ok(complete, '报文区间内无冲突 => 完整');
  assert.strictEqual(complete.end, req.length);
  assert.strictEqual(complete.conflicts.length, 0);
});

test('HTTP：JSON 冻结导出包含 messages、包号证据与 owners，且为同一快照', () => {
  tsCounter = 21800000;
  const req = Buffer.from('GET /j HTTP/1.1\r\n\r\n');
  const buf = httpStream([req.slice(0, 5), req.slice(5)]);
  const { model } = buildFromBuf(buf);
  const snap = ReassemblyLib.freezeModel(model, { fileName: 'j.pcap' });
  const json = JSON.stringify(snap); // 导出路径
  const reparsed = JSON.parse(json);
  const d = reparsed.model.connections[0].directionAtoB;
  const m = d.http.messages[0];
  assert.strictEqual(m.status, 'complete');
  assert.ok(Array.isArray(m.evidence.packets) && m.evidence.packets.length === 2);
  assert.strictEqual(m.evidence.packets[0].pktNumber, 1);
  assert.strictEqual(m.evidence.packets[1].pktNumber, 2);
  assert.ok(Array.isArray(d.runs[0].owners));
  assert.ok(snap.snapshotId);
});

// ---------------- 运行 ----------------

let pass = 0;
let fail = 0;
for (const t of tests) {
  try {
    t.fn();
    console.log('  ✓ ' + t.name);
    pass++;
  } catch (e) {
    console.error('  ✗ ' + t.name);
    console.error('    ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n    ') : e));
    fail++;
  }
}
console.log('\n' + pass + ' 通过，' + fail + ' 失败');
process.exit(fail ? 1 : 0);
