const fs = require('fs');
const path = require('path');

const distFile = path.join(__dirname, '..', 'dist', 'index.js');

if (fs.existsSync(distFile)) {
  let content = fs.readFileSync(distFile, 'utf8');
  
  // Ensure shebang is present
  if (!content.startsWith('#!/usr/bin/env node')) {
    content = '#!/usr/bin/env node\n' + content;
    fs.writeFileSync(distFile, content, 'utf8');
  }
  
  // Make executable (npm handles this, but ensure it)
  try {
    fs.chmodSync(distFile, '755');
  } catch (err) {
    // Ignore chmod errors on Windows
  }
  
  console.log('✓ Bin file prepared');
}
