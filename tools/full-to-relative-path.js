const path = require('path');

const args = process.argv.slice(2);
const relativePaths = args.map(filePath => path.relative(process.cwd(), filePath));

console.log(relativePaths.join(' '));
