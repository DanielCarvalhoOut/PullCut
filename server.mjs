// PullCut — servidor local: baixa vídeo/áudio de uma URL (inteiro ou trecho) via yt-dlp.
// Só escuta em 127.0.0.1. Sem dependências externas além de yt-dlp.exe e FFmpeg.
// O Painel geral (../Painel) o usa como plugin, pela API HTTP abaixo.

import http from 'node:http';
import { spawn, execFileSync } from 'node:child_process';
import { readFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { Readable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PULLCUT_PORT || 4747);
const YTDLP = path.join(ROOT, 'bin', 'yt-dlp.exe');

// pullcut.config.json (opcional, modelo em pullcut.config.exemplo.json): "drive" é a pasta do estúdio no
// Google Drive; "destinos" acrescenta ou troca pastas de saída ({ id: { nome, pasta } }).
const CONFIG = JSON.parse(await readFile(path.join(ROOT, 'pullcut.config.json'), 'utf8').catch(() => '{}'));
const DRIVE = process.env.PULLCUT_DRIVE || CONFIG.drive || 'G:\\Meu Drive\\EditorVideos';
const DESTINOS = {
  pullcut: { nome: 'Downloads do PullCut', pasta: path.join(ROOT, 'downloads') },
  hyperframes: { nome: 'HyperFrames (Drive)', pasta: path.join(DRIVE, 'HyperFrames', 'entrada') },
  filmcraft: { nome: 'FilmCraft (Drive)', pasta: path.join(DRIVE, 'FilmCraft', 'entrada') },
  ...(CONFIG.destinos || {}),
};

const FORMATOS_AUDIO = ['mp3', 'm4a', 'wav'];

// ---------- proteção das rotas ----------
// Escutar só em 127.0.0.1 não basta: uma página aberta no navegador ainda consegue mandar pedidos para cá.
// - Host conhecido: barra DNS rebinding (um domínio externo que passa a apontar para 127.0.0.1).
// - Métodos: só GET, HEAD e POST. OPTIONS (pré-voo de CORS) é recusado, então nenhum outro site ganha licença.
// - /api/ só da própria origem: Sec-Fetch-Site "cross-site" e "same-site" (outra porta de localhost) são recusados.
// - POST: Origin, quando vem, tem de ser o PullCut, e o corpo só com Content-Type application/json, que obriga
//   o navegador a pedir licença (CORS) antes. Um formulário ou fetch "simples" de outro site não chega aqui.
// - A página só pode ser embutida pelo Painel (aba PullCut), sem clickjacking por outros sites.
// Pedidos sem Origin (o Painel pelo Node, curl) continuam funcionando. Não é autenticação: qualquer programa
// rodando no próprio PC ainda pode falar com o PullCut.
const HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]'].map((h) => `${h}:${PORT}`));
const ORIGENS = new Set([...HOSTS].map((h) => `http://${h}`));
const PAINEL = new URL(process.env.PULLCUT_PAINEL || CONFIG.painel || 'http://127.0.0.1:4700');
const MOLDURA = ['127.0.0.1', 'localhost'].map((h) => `http://${h}:${PAINEL.port || 80}`).join(' ');
const CABECALHOS = {
  'Content-Security-Policy': `frame-ancestors 'self' ${MOLDURA}`,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

class ErroHttp extends Error {
  constructor(status, mensagem) {
    super(mensagem);
    this.status = status;
  }
}

// Devolve null se o pedido pode seguir, ou [status, mensagem] para recusar.
function checarPedido(req, rota) {
  if (!HOSTS.has(String(req.headers.host || '').toLowerCase())) return [421, 'Host não permitido.'];
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) return [405, 'Método não permitido.'];
  const site = req.headers['sec-fetch-site'];
  if (rota.startsWith('/api/') && (site === 'cross-site' || site === 'same-site')) return [403, 'Pedido de outro site recusado.'];
  if (req.method !== 'POST') return null;
  const origem = req.headers.origin;
  // "null" (iframe com sandbox, arquivo local) também cai aqui: não está na lista.
  if (origem !== undefined && !ORIGENS.has(origem)) return [403, 'Origem não permitida.'];
  if (site && site !== 'same-origin' && site !== 'none') return [403, 'Pedido de outra origem recusado.'];
  if (!/^application\/json\s*(;|$)/i.test(req.headers['content-type'] || '')) return [415, 'Use Content-Type: application/json.'];
  return null;
}

// A prévia repassa endereços que vêm da página analisada (um site qualquer). Nunca para o próprio PC nem
// para a rede local: senão uma página maliciosa faria o PullCut ler o Painel, o roteador etc.
function ipInterno(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  const v6 = ip.toLowerCase();
  // IPv4 dentro de IPv6 (::ffff:127.0.0.1, que a URL normaliza para ::ffff:7f00:1): confere o IPv4.
  const mapeado = v6.match(/^::ffff:(?:([\d.]+)|([\da-f]{1,4}):([\da-f]{1,4}))$/);
  if (mapeado) {
    if (mapeado[1]) return ipInterno(mapeado[1]);
    const [x, y] = [parseInt(mapeado[2], 16), parseInt(mapeado[3], 16)];
    return ipInterno(`${x >> 8}.${x & 255}.${y >> 8}.${y & 255}`);
  }
  return v6 === '::' || v6 === '::1' || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || v6.startsWith('ff');
}

async function enderecoExterno(texto) {
  let u;
  try { u = new URL(texto); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const ips = net.isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((r) => r.address);
  return ips.length > 0 && !ips.some(ipInterno);
}

// FFmpeg pode não estar no PATH de um shell aberto antes da instalação pelo winget.
function acharFfmpeg() {
  try {
    const saida = execFileSync('where', ['ffmpeg'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const primeiro = saida.split(/\r?\n/).find(Boolean);
    if (primeiro) return path.dirname(primeiro);
  } catch {}
  const winget = path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
  try {
    for (const pkg of execFileSync('cmd', ['/c', 'dir', '/b', winget], { encoding: 'utf8' }).split(/\r?\n/)) {
      if (!pkg.startsWith('Gyan.FFmpeg')) continue;
      const base = path.join(winget, pkg);
      for (const sub of execFileSync('cmd', ['/c', 'dir', '/b', base], { encoding: 'utf8' }).split(/\r?\n/)) {
        const bin = path.join(base, sub, 'bin');
        if (sub && existsSync(path.join(bin, 'ffmpeg.exe'))) return bin;
      }
    }
  } catch {}
  return null;
}
const FFMPEG_DIR = acharFfmpeg();

// ---------- utilidades ----------

function json(res, status, corpo) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(corpo));
}

async function lerCorpo(req) {
  let dados = '';
  for await (const parte of req) {
    dados += parte;
    if (dados.length > 1e5) throw new ErroHttp(413, 'Corpo grande demais.');
  }
  if (!dados) return {};
  let corpo;
  try {
    corpo = JSON.parse(dados);
  } catch {
    throw new ErroHttp(400, 'JSON inválido no corpo.');
  }
  if (!corpo || typeof corpo !== 'object' || Array.isArray(corpo)) throw new ErroHttp(400, 'O corpo deve ser um objeto JSON.');
  return corpo;
}

function urlValida(texto) {
  try {
    const u = new URL(String(texto).trim());
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

// Aceita "90", "1:30", "01:02:03" e "1:30.5"; devolve segundos ou null.
function paraSegundos(texto) {
  if (texto === undefined || texto === null || String(texto).trim() === '') return null;
  const partes = String(texto).trim().split(':');
  if (partes.length > 3 || partes.some((p) => !/^\d+(\.\d+)?$/.test(p))) return NaN;
  return partes.reduce((total, p) => total * 60 + Number(p), 0);
}

function rodarYtdlp(args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(YTDLP, args, { windowsHide: true });
    let out = '';
    let err = '';
    proc.stdout.on('data', (d) => (out += d));
    proc.stderr.on('data', (d) => (err += d));
    proc.on('error', reject);
    proc.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(limparErro(err) || `yt-dlp saiu com código ${code}`))));
  });
}

function limparErro(texto) {
  const linhas = String(texto).split(/\r?\n/).filter((l) => l.startsWith('ERROR'));
  return (linhas.at(-1) || String(texto).trim().split(/\r?\n/).at(-1) || '').replace(/^ERROR:\s*/, '');
}

// ---------- análise da URL ----------

async function analisar(url) {
  const bruto = await rodarYtdlp(['-J', '--no-playlist', '--no-warnings', url]);
  const info = JSON.parse(bruto);
  const alturas = new Set();
  let temAudio = false;
  for (const f of info.formats || []) {
    if (f.vcodec && f.vcodec !== 'none' && f.height) alturas.add(f.height);
    if (f.acodec && f.acodec !== 'none') temAudio = true;
  }
  if (!alturas.size && info.height) alturas.add(info.height);
  const previa = registrarPrevia(info);
  return {
    previa,
    url,
    titulo: info.title,
    canal: info.uploader || info.channel || info.extractor_key,
    site: info.extractor_key,
    duracao: info.duration || null,
    miniatura: info.thumbnail || null,
    alturas: [...alturas].sort((a, b) => b - a),
    temAudio,
    aoVivo: Boolean(info.is_live),
  };
}

// ---------- prévia (player do monitor) ----------

// Guarda o endereço direto de um formato com vídeo + áudio juntos (até 720p) para o <video> da página.
// A página nunca vê esse endereço: ela pede /api/previa/<id> e o servidor repassa com os cabeçalhos certos.
const previas = new Map();
const VALIDADE_PREVIA = 6 * 3600 * 1000;

function registrarPrevia(info) {
  for (const [id, p] of previas) if (Date.now() - p.criado > VALIDADE_PREVIA) previas.delete(id);
  const diretos = (info.formats || []).filter((f) => f.url && /^https?$/.test(f.protocol || ''));
  const temVideo = (f) => f.vcodec && f.vcodec !== 'none';
  const temAudio = (f) => f.acodec && f.acodec !== 'none';
  const guardar = (f) => {
    const id = randomUUID();
    previas.set(id, { url: f.url, headers: f.http_headers || info.http_headers || {}, criado: Date.now() });
    return id;
  };
  const porAltura = (lista, limite) => {
    const ate = lista.filter((f) => (f.height || 0) <= limite).sort((a, b) => (b.height || 0) - (a.height || 0));
    return ate[0] || [...lista].sort((a, b) => (a.height || 0) - (b.height || 0))[0];
  };

  // 1) Um arquivo com vídeo + áudio juntos (a maioria dos sites).
  const juntos = diretos.filter((f) => temVideo(f) && temAudio(f));
  if (juntos.length) {
    const f = porAltura(juntos, 720);
    return { video: guardar(f), audio: null, altura: f.height || null };
  }

  // 2) Vídeo e áudio separados (YouTube): a página toca os dois em sincronia.
  // Vídeo leve (até 480p), de preferência H.264, que todo navegador decodifica sem esforço.
  const soVideo = diretos.filter((f) => temVideo(f) && !temAudio(f));
  const soAudio = diretos.filter((f) => temAudio(f) && !temVideo(f) && !String(f.format_id).includes('drc'));
  if (!soVideo.length) return null;
  const h264 = soVideo.filter((f) => String(f.vcodec).startsWith('avc1'));
  const v = porAltura(h264.length ? h264 : soVideo, 480);
  const m4a = soAudio.filter((f) => f.ext === 'm4a');
  const a = (m4a.length ? m4a : soAudio).sort((x, y) => (y.abr || 0) - (x.abr || 0))[0];
  return { video: guardar(v), audio: a ? guardar(a) : null, altura: v.height || null };
}

async function servirPrevia(req, res, id) {
  const previa = previas.get(id);
  if (!previa) return json(res, 404, { erro: 'Prévia expirada. Analise a URL de novo.' });
  const controle = new AbortController();
  res.on('close', () => controle.abort());
  const headers = { ...previa.headers, 'Accept-Encoding': 'identity' };
  if (req.headers.range) headers.Range = req.headers.range;
  try {
    // Segue os redirecionamentos à mão, conferindo cada destino (um redirect também poderia apontar para dentro).
    let alvo = previa.url;
    let origem;
    for (let saltos = 0; ; saltos++) {
      if (saltos > 5 || !(await enderecoExterno(alvo))) return json(res, 403, { erro: 'Prévia recusada: endereço não permitido.' });
      origem = await fetch(alvo, { headers, signal: controle.signal, redirect: 'manual' });
      const proximo = origem.headers.get('location');
      if (origem.status < 300 || origem.status >= 400 || !proximo) break;
      await origem.body?.cancel();
      alvo = new URL(proximo, alvo).href;
    }
    const repassar = {};
    for (const h of ['content-type', 'content-length', 'content-range', 'accept-ranges']) {
      const v = origem.headers.get(h);
      if (v) repassar[h] = v;
    }
    res.writeHead(origem.status, repassar);
    if (!origem.body) return res.end();
    Readable.fromWeb(origem.body).on('error', () => res.destroy()).pipe(res);
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (e.name !== 'AbortError') json(res, 502, { erro: 'O site recusou a prévia.' });
  }
}

// ---------- fila de downloads ----------

const tarefas = new Map();
const ouvintes = new Set();
let proximoId = 1;

function publicar(tarefa) {
  const dados = `data: ${JSON.stringify(resumo(tarefa))}\n\n`;
  for (const res of ouvintes) res.write(dados);
}

function resumo(t) {
  const { proc, ...resto } = t;
  return resto;
}

function montarArgs(pedido, pasta, arquivoProgresso) {
  const args = [
    '--no-playlist', '--newline', '--progress', '--no-warnings', '--windows-filenames',
    '--progress-template', 'download:PC|%(progress._percent_str)s|%(progress._speed_str)s|%(progress._eta_str)s',
    '--print', 'after_move:FINAL|%(filepath)s',
    '-P', pasta,
  ];
  if (FFMPEG_DIR) args.push('--ffmpeg-location', FFMPEG_DIR);

  let sufixo = '';
  if (pedido.trecho) {
    const { inicio, fim } = pedido.trecho;
    args.push('--download-sections', `*${inicio}-${fim}`);
    // Corte preciso recodifica o trecho inteiro (lento em 4K); o rápido copia e começa no keyframe mais próximo.
    if (pedido.preciso) args.push('--force-keyframes-at-cuts');
    // Trechos são baixados pelo FFmpeg, que o yt-dlp roda em silêncio: o progresso vem deste arquivo.
    // Barras normais: o yt-dlp divide os argumentos como shell POSIX e comeria as invertidas.
    args.push('--downloader-args', `ffmpeg:-progress ${arquivoProgresso.replace(/\\/g, '/')} -stats_period 0.5`);
    sufixo = ` [${fmtTempo(inicio, true)}-${fmtTempo(fim, true)}]`;
  }

  if (pedido.tipo === 'audio') {
    args.push('-f', 'ba/b', '-x', '--audio-format', pedido.formatoAudio, '--audio-quality', '0');
  } else {
    const h = pedido.altura;
    const filtro = h ? `[height<=${h}]` : '';
    // Prefere H.264 + AAC em MP4: abre em qualquer editor sem conversão.
    args.push('-f', `bv*${filtro}+ba/b${filtro}/bv*+ba/b`, '-S', 'vcodec:h264,acodec:aac', '--merge-output-format', 'mp4');
    if (h) sufixo += ` ${h}p`;
  }

  args.push('-o', `%(title).80B${sufixo.replace(/[%]/g, '')} [%(id)s].%(ext)s`, pedido.url);
  return args;
}

function fmtTempo(seg, paraArquivo = false) {
  const s = Math.floor(seg % 60), m = Math.floor((seg / 60) % 60), h = Math.floor(seg / 3600);
  const p = (n) => String(n).padStart(2, '0');
  const sep = paraArquivo ? '.' : ':';
  return h ? `${h}${sep}${p(m)}${sep}${p(s)}` : `${m}${sep}${p(s)}`;
}

async function iniciarDownload(pedido) {
  const destino = DESTINOS[pedido.destino];
  await mkdir(destino.pasta, { recursive: true });

  const tarefa = {
    id: proximoId++,
    titulo: pedido.titulo || pedido.url,
    miniatura: pedido.miniatura || null,
    descricao: descrever(pedido),
    destino: destino.nome,
    pasta: destino.pasta,
    estado: 'baixando',
    progresso: 0,
    velocidade: '',
    restante: '',
    arquivo: null,
    erro: null,
    criadoEm: Date.now(),
  };
  tarefas.set(tarefa.id, tarefa);

  const arquivoProgresso = path.join(os.tmpdir(), `pullcut-${process.pid}-${tarefa.id}.txt`);
  const proc = spawn(YTDLP, montarArgs(pedido, destino.pasta, arquivoProgresso), { windowsHide: true });
  tarefa.proc = proc;
  let stderr = '';
  let partes = 0;
  let ultimoPct = 0;

  // Trecho: lê o arquivo de progresso do FFmpeg (out_time_us = quanto do trecho já foi gravado).
  let leitor = null;
  if (pedido.trecho) {
    const duracao = pedido.trecho.fim - pedido.trecho.inicio;
    leitor = setInterval(async () => {
      let texto;
      try { texto = await readFile(arquivoProgresso, 'utf8'); } catch { return; }
      const tempos = [...texto.matchAll(/out_time_us=(\d+)/g)];
      const velocidades = [...texto.matchAll(/speed=\s*([\d.]+)x/g)];
      if (!tempos.length) return;
      const feito = Number(tempos.at(-1)[1]) / 1e6;
      const vel = velocidades.length ? Number(velocidades.at(-1)[1]) : 0;
      tarefa.progresso = Math.min(99, Math.round((feito / duracao) * 1000) / 10);
      tarefa.velocidade = vel ? `${vel.toFixed(2)}x tempo real` : '';
      tarefa.restante = vel ? fmtTempo(Math.max(0, duracao - feito) / vel) : '';
      tarefa.estado = /progress=end\s*$/.test(texto) ? 'processando' : 'baixando';
      publicar(tarefa);
    }, 700);
  }

  const linhaOut = (linha) => {
    // Em trechos o yt-dlp só manda "NA" aqui; o progresso real vem do arquivo do FFmpeg.
    if (linha.startsWith('PC|') && !pedido.trecho) {
      const [, pct, vel, eta] = linha.split('|');
      const n = parseFloat(pct);
      if (!Number.isNaN(n)) {
        // vídeo + áudio vêm em dois downloads; mostra o total como uma barra só.
        if (n < ultimoPct - 50) partes++;
        ultimoPct = n;
        const total = pedido.tipo === 'audio' ? n : Math.min(99, (partes * 100 + n) / 2);
        tarefa.progresso = Math.max(tarefa.progresso, Math.round(total * 10) / 10);
      }
      tarefa.velocidade = (vel || '').trim();
      tarefa.restante = (eta || '').trim();
      tarefa.estado = n >= 100 ? 'processando' : 'baixando';
      publicar(tarefa);
    } else if (linha.startsWith('FINAL|')) {
      tarefa.arquivo = linha.slice(6).trim();
    }
  };

  let buffer = '';
  proc.stdout.on('data', (d) => {
    buffer += d;
    const linhas = buffer.split(/\r?\n/);
    buffer = linhas.pop();
    linhas.forEach(linhaOut);
  });
  proc.stderr.on('data', (d) => (stderr += d));
  proc.on('close', (code) => {
    if (buffer) linhaOut(buffer);
    delete tarefa.proc;
    if (leitor) {
      clearInterval(leitor);
      rm(arquivoProgresso, { force: true }).catch(() => {});
    }
    if (tarefa.estado === 'cancelado') return publicar(tarefa);
    if (code === 0) {
      tarefa.estado = 'concluido';
      tarefa.progresso = 100;
      tarefa.restante = '';
      tarefa.velocidade = '';
    } else {
      tarefa.estado = 'erro';
      tarefa.erro = limparErro(stderr) || `yt-dlp saiu com código ${code}`;
    }
    publicar(tarefa);
  });
  proc.on('error', (e) => {
    tarefa.estado = 'erro';
    tarefa.erro = e.message;
    publicar(tarefa);
  });

  publicar(tarefa);
  return tarefa;
}

function descrever(p) {
  const tipo = p.tipo === 'audio' ? `Áudio ${p.formatoAudio.toUpperCase()}` : `Vídeo ${p.altura ? p.altura + 'p' : 'melhor qualidade'}`;
  const trecho = p.trecho ? `${fmtTempo(p.trecho.inicio)} – ${fmtTempo(p.trecho.fim)} (${p.preciso ? 'preciso' : 'rápido'})` : 'inteiro';
  return `${tipo} · ${trecho}`;
}

function validarPedido(c) {
  const url = urlValida(c.url);
  if (!url) return { erro: 'URL inválida (use http ou https).' };
  if (!DESTINOS[c.destino]) return { erro: 'Destino desconhecido.' };
  const tipo = c.tipo === 'audio' ? 'audio' : 'video';
  const formatoAudio = FORMATOS_AUDIO.includes(c.formatoAudio) ? c.formatoAudio : 'mp3';
  const altura = c.altura ? Number(c.altura) : null;
  if (altura !== null && (!Number.isInteger(altura) || altura < 100 || altura > 8640)) return { erro: 'Qualidade inválida.' };

  let trecho = null;
  if (c.trecho) {
    const inicio = paraSegundos(c.trecho.inicio) ?? 0;
    const fim = paraSegundos(c.trecho.fim);
    if (Number.isNaN(inicio) || Number.isNaN(fim) || fim === null) return { erro: 'Tempo do trecho inválido. Use 1:30 ou 01:02:03.' };
    if (fim <= inicio) return { erro: 'O fim do trecho precisa ser depois do início.' };
    if (c.duracao && inicio >= c.duracao) return { erro: 'O início passa do fim do vídeo.' };
    trecho = { inicio, fim: c.duracao ? Math.min(fim, c.duracao) : fim };
  }

  return {
    pedido: {
      url, tipo, formatoAudio, altura, trecho, preciso: c.preciso === true, destino: c.destino,
      titulo: typeof c.titulo === 'string' ? c.titulo.slice(0, 300) : null,
      miniatura: urlValida(c.miniatura),
    },
  };
}

// ---------- abrir pasta no Explorer ----------

function abrirNoExplorer(tarefa) {
  if (tarefa.arquivo && existsSync(tarefa.arquivo)) {
    spawn('explorer.exe', [`/select,${tarefa.arquivo}`], { detached: true }).unref();
  } else {
    spawn('explorer.exe', [tarefa.pasta], { detached: true }).unref();
  }
}

// ---------- servidor HTTP ----------

const servidor = http.createServer(async (req, res) => {
  for (const [k, v] of Object.entries(CABECALHOS)) res.setHeader(k, v);
  let url;
  try {
    url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  } catch {
    return json(res, 400, { erro: 'Endereço inválido.' });
  }
  const barrado = checarPedido(req, url.pathname);
  if (barrado) {
    // Não lê o corpo: responde e fecha a conexão, para o resto não virar o "próximo pedido".
    if (!req.complete) res.setHeader('Connection', 'close');
    return json(res, barrado[0], { erro: barrado[1] });
  }
  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(await readFile(path.join(ROOT, 'public', 'index.html')));
    }

    if (req.method === 'GET' && url.pathname === '/api/estado') {
      const destinos = Object.entries(DESTINOS).map(([id, d]) => ({ id, nome: d.nome, pasta: d.pasta, disponivel: existsSync(path.parse(d.pasta).root) }));
      return json(res, 200, {
        ffmpeg: Boolean(FFMPEG_DIR),
        ytdlp: existsSync(YTDLP),
        destinos,
        tarefas: [...tarefas.values()].map(resumo).reverse(),
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/eventos') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write(': ok\n\n');
      ouvintes.add(res);
      req.on('close', () => ouvintes.delete(res));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/analisar') {
      const corpo = await lerCorpo(req);
      const alvo = urlValida(corpo.url);
      if (!alvo) return json(res, 400, { erro: 'URL inválida (use http ou https).' });
      try {
        return json(res, 200, await analisar(alvo));
      } catch (e) {
        return json(res, 422, { erro: e.message });
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/baixar') {
      const { pedido, erro } = validarPedido(await lerCorpo(req));
      if (erro) return json(res, 400, { erro });
      const tarefa = await iniciarDownload(pedido);
      return json(res, 200, resumo(tarefa));
    }

    const previa = url.pathname.match(/^\/api\/previa\/([\w-]+)$/);
    if (req.method === 'GET' && previa) return servirPrevia(req, res, previa[1]);

    const acao = url.pathname.match(/^\/api\/tarefas\/(\d+)\/(cancelar|abrir)$/);
    if (req.method === 'POST' && acao) {
      const tarefa = tarefas.get(Number(acao[1]));
      if (!tarefa) return json(res, 404, { erro: 'Tarefa não encontrada.' });
      if (acao[2] === 'cancelar' && tarefa.proc) {
        tarefa.estado = 'cancelado';
        spawn('taskkill', ['/pid', String(tarefa.proc.pid), '/t', '/f'], { windowsHide: true });
      }
      if (acao[2] === 'abrir') abrirNoExplorer(tarefa);
      return json(res, 200, resumo(tarefa));
    }

    json(res, 404, { erro: 'Não encontrado.' });
  } catch (e) {
    if (res.headersSent) return res.destroy();
    if (!req.complete) res.setHeader('Connection', 'close');
    if (e instanceof ErroHttp) return json(res, e.status, { erro: e.message });
    // O detalhe (caminhos, pilha) fica só no console.
    console.error(`[pullcut] ${req.method} ${url.pathname}`, e);
    json(res, 500, { erro: 'Erro interno do PullCut. Veja o console do servidor.' });
  }
});

servidor.listen(PORT, '127.0.0.1', () => {
  console.log(`PullCut rodando em http://127.0.0.1:${PORT}`);
  if (!FFMPEG_DIR) console.warn('Aviso: FFmpeg não encontrado — cortes, junção de áudio/vídeo e conversão de áudio vão falhar.');
});
