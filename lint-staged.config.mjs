import path from 'path';

/**
 * Issue: We need to convert the absolute paths of the staged files to relative paths inside the container.
 */
const localPathToRelativeInsideWpEnvContainer = (stagedFiles) => {
    return stagedFiles.map(filePath => path.relative(process.cwd(), filePath)).join(' ');
};

export default {
    '*.php': (stagedFiles) => `npm run lint -- ${localPathToRelativeInsideWpEnvContainer(stagedFiles)}`,
};
