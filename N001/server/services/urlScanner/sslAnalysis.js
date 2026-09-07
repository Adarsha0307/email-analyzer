import tls from 'node:tls';

export function checkSslCertificate(hostname, port = 443, timeout = 8000) {
  return new Promise((resolve) => {
    const findings = [];
    let riskScore = 0;
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: true, timeout });
    let settled = false;

    function finish(result) {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    }

    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      if (!certificate || Object.keys(certificate).length === 0) {
        return finish({ valid: false, protocol, findings: [{ severity: 'medium', category: 'ssl', title: 'No certificate details', description: 'The server did not provide readable certificate details.' }], riskScore: 20 });
      }

      const now = new Date();
      const validTo = new Date(certificate.valid_to);
      const validFrom = new Date(certificate.valid_from);
      const remainingDays = Math.floor((validTo - now) / 86400000);

      if (validTo < now) {
        findings.push({ severity: 'critical', category: 'ssl', title: 'SSL certificate expired', description: `Certificate expired on ${validTo.toISOString().split('T')[0]}.` });
        riskScore += 40;
      }
      if (validFrom > now) {
        findings.push({ severity: 'high', category: 'ssl', title: 'SSL certificate not yet valid', description: `Certificate becomes valid on ${validFrom.toISOString().split('T')[0]}.` });
        riskScore += 30;
      }
      if (remainingDays >= 0 && remainingDays < 30) {
        findings.push({ severity: 'medium', category: 'ssl', title: 'SSL certificate expiring soon', description: `Certificate expires in ${remainingDays} days.` });
        riskScore += 15;
      }
      if (!socket.authorized) {
        findings.push({ severity: 'high', category: 'ssl', title: 'SSL certificate not trusted', description: `Certificate validation failed: ${socket.authorizationError || 'unknown error'}.` });
        riskScore += 35;
      }
      if (certificate.issuer?.O) findings.push({ severity: 'info', category: 'ssl', title: 'Certificate issuer', description: `Issued by ${certificate.issuer.O}.` });
      if (protocol && /SSLv[23]|TLSv1(?:\.0|\.1)?$/.test(protocol)) {
        findings.push({ severity: 'high', category: 'ssl', title: 'Outdated TLS protocol', description: `The server negotiated ${protocol}.` });
        riskScore += 30;
      }

      return finish({
        valid: socket.authorized,
        protocol,
        issuer: certificate.issuer?.O || 'Unknown',
        subject: certificate.subject?.CN || 'Unknown',
        validFrom: certificate.valid_from,
        validTo: certificate.valid_to,
        remainingDays: Math.max(0, remainingDays),
        expired: validTo < now,
        findings,
        riskScore: Math.min(100, riskScore),
      });
    });

    socket.once('error', (error) => finish({
      valid: false,
      findings: [{ severity: 'high', category: 'ssl', title: 'SSL connection failed', description: `Could not establish TLS: ${error.message}` }],
      riskScore: 50,
      error: error.message,
    }));
    socket.once('timeout', () => finish({
      valid: false,
      findings: [{ severity: 'medium', category: 'ssl', title: 'SSL connection timed out', description: `TLS handshake exceeded ${timeout}ms.` }],
      riskScore: 20,
    }));
  });
}
