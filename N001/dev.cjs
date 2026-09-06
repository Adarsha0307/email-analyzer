const { spawn } = require('child_process');

const children = [
  spawn('npm run dev:backend', { stdio: 'inherit', shell: true }),
  spawn('npm run dev:frontend', { stdio: 'inherit', shell: true }),
];

let stopping = false;

function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill();
  setTimeout(() => process.exit(exitCode), 100);
}

for (const child of children) {
  child.on('error', (error) => {
    console.error(error.message);
    stop(1);
  });
  child.on('exit', (code) => {
    if (!stopping && code) stop(code);
  });
}

process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
