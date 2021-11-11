// const enfaceAuth = require('./dist/enface.auth.node.js');
const { createChallenge, checkChallenge } = require('./src/blockchain');

// console.log({ createChallenge, checkChallenge });

const main = async () => {
  const name = 'anton';
  const challenge = await createChallenge(name);
  console.log({ challenge });
};

main();
