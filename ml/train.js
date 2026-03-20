/**
 * Standalone ML training script — run with: npm run train
 */
const { trainModel, getModelInfo } = require('./detector');

async function main() {
  console.log('VulnLab ML Trainer');
  console.log('══════════════════════════════════════');
  const before = await getModelInfo();
  console.log(`Current model: v${before.version}, ${before.sample_count} samples\n`);

  const result = await trainModel();
  if (result.success) {
    console.log(`✓ Training complete!`);
    console.log(`  Model version : v${result.version}`);
    console.log(`  Samples used  : ${result.samples}`);
    console.log(`  Epochs        : ${result.epochs}`);
    console.log(`  Trained at    : ${result.trained_at}`);
    console.log('\nModel saved to data/model.json');
  } else {
    console.log(`✗ Training failed: ${result.message}`);
    console.log('Add more labeled samples via the admin dashboard first.');
  }
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
