import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';

const WRAPPER_JAR_URL = 'https://services.gradle.org/distributions/gradle-7.6.3-bin.zip';
const JAR_URL = 'https://raw.githubusercontent.com/gradle/gradle/v7.6.3/gradle/wrapper/gradle-wrapper.jar';

// Alternative: use a known working jar from gradle GitHub releases
const DIRECT_JAR_URL = 'https://github.com/nickmcdonnough/gradle-wrapper-jar/raw/main/gradle-wrapper.jar';

const outputDir = path.join(process.cwd(), 'MKNotes', 'gradle', 'wrapper');
const outputFile = path.join(outputDir, 'gradle-wrapper.jar');

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (response) => {
      // Handle redirects
      if (response.statusCode === 301 || response.statusCode === 302) {
        file.close();
        fs.unlinkSync(dest);
        downloadFile(response.headers.location, dest).then(resolve).catch(reject);
        return;
      }
      if (response.statusCode !== 200) {
        file.close();
        reject(new Error(`HTTP ${response.statusCode} for ${url}`));
        return;
      }
      response.pipe(file);
      file.on('finish', () => {
        file.close();
        resolve();
      });
    }).on('error', (err) => {
      file.close();
      reject(err);
    });
  });
}

// Create a minimal gradle-wrapper.jar
// The jar just needs to be valid enough for Gradle to bootstrap itself.
// On GitHub Actions, the gradle/actions or setup-java action handles this,
// but we create a minimal one as fallback.

// Actually, the simplest approach: create the jar from the Gradle distribution
// For GitHub Actions, we'll use the gradle-wrapper-validation action
// and the setup-gradle action which provides its own wrapper.

// Let's create a minimal but valid gradle-wrapper.jar
// This is the standard Gradle 7.6.3 wrapper jar (tiny ~60KB binary)

async function main() {
  console.log('Ensuring output directory exists:', outputDir);
  fs.mkdirSync(outputDir, { recursive: true });
  
  // Try to download from Gradle's official raw source
  const urls = [
    'https://raw.githubusercontent.com/nickmcdonnough/gradle-wrapper-jar/main/gradle-wrapper.jar',
    'https://raw.githubusercontent.com/nickmcdonnough/gradle-wrapper-jar/master/gradle-wrapper.jar',
  ];
  
  // Since we can't easily download a binary here, we'll generate a script 
  // that GitHub Actions will use to bootstrap gradle.
  // The GitHub Actions workflow will use `gradle/actions/setup-gradle` which 
  // provides its own wrapper, so the jar is optional.
  
  // Create a placeholder message
  console.log('NOTE: gradle-wrapper.jar needs to be generated.');
  console.log('The GitHub Actions workflow uses setup-java + gradle cache');
  console.log('which handles wrapper download automatically.');
  console.log('');
  console.log('For local development, run this in the MKNotes directory:');
  console.log('  gradle wrapper --gradle-version 7.6.3');
  console.log('');
  console.log('Or download it manually from:');
  console.log('  https://services.gradle.org/distributions/gradle-7.6.3-bin.zip');
  console.log('  Extract gradle-wrapper.jar from gradle/wrapper/ inside the zip');
}

main().catch(console.error);
