import dgram from 'node:dgram';
import net from 'node:net';
import { config } from '../../config.js';
import { ingest } from './store.js';

/**
 * Recetores de syslog. Escutam em UDP e/ou TCP e entregam cada linha ao store.
 * O arranque é tolerante a falhas: se uma porta estiver ocupada ou sem
 * permissões, regista um aviso e continua — nunca derruba o processo.
 */

let udpServer: dgram.Socket | null = null;
let tcpServer: net.Server | null = null;

function startUdp(): void {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  sock.on('message', (msg, rinfo) => {
    // Um datagrama pode conter várias linhas.
    for (const line of msg.toString('utf8').split(/\r?\n/)) {
      if (line.trim()) {
        try { ingest(line, rinfo.address); } catch { /* linha malformada — ignora */ }
      }
    }
  });
  sock.on('error', (err) => {
    console.warn(`  · Syslog UDP indisponível (${(err as NodeJS.ErrnoException).code || err.message}) — recetor UDP desligado`);
    sock.close();
    udpServer = null;
  });
  sock.bind(config.syslog.udpPort, config.syslog.bind, () => {
    console.log(`  · Syslog UDP a escutar em ${config.syslog.bind}:${config.syslog.udpPort}`);
  });
  udpServer = sock;
}

function startTcp(): void {
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    let acc = '';
    socket.on('data', (chunk) => {
      acc += chunk;
      let nl: number;
      // Processa linha a linha; protege contra linhas gigantes.
      while ((nl = acc.indexOf('\n')) !== -1) {
        const line = acc.slice(0, nl);
        acc = acc.slice(nl + 1);
        if (line.trim()) {
          try { ingest(line, socket.remoteAddress?.replace(/^::ffff:/, '') || ''); } catch { /* ignora */ }
        }
      }
      if (acc.length > 64 * 1024) acc = ''; // descarta acumulação anómala
    });
    socket.on('error', () => socket.destroy());
  });
  server.on('error', (err) => {
    console.warn(`  · Syslog TCP indisponível (${(err as NodeJS.ErrnoException).code || err.message}) — recetor TCP desligado`);
    tcpServer = null;
  });
  server.listen(config.syslog.tcpPort, config.syslog.bind, () => {
    console.log(`  · Syslog TCP a escutar em ${config.syslog.bind}:${config.syslog.tcpPort}`);
  });
  tcpServer = server;
}

/** Arranca os recetores se a ingestão de syslog estiver ativa no arranque. */
export function startSyslog(): void {
  if (!config.syslog.enabled) {
    console.log('  · Ingestão de syslog: desativada (SYSLOG_ENABLED=false)');
    return;
  }
  enableSyslog();
}

/** Liga os recetores em tempo de execução (idempotente — não re-vincula). */
export function enableSyslog(): void {
  if (config.syslog.udp && !udpServer) startUdp();
  if (config.syslog.tcp && !tcpServer) startTcp();
}

/** Encerra os recetores (testes / shutdown gracioso). */
export function stopSyslog(): void {
  udpServer?.close();
  tcpServer?.close();
  udpServer = null;
  tcpServer = null;
}
