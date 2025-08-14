const express = require('express');
const admin = require('firebase-admin');

// Correctly handle the private key with escaped newlines
const serviceAccountKeyString = process.env.FIREBASE_SERVICE_ACCOUNT_KEY.replace(/\\n/g, '\n');
const serviceAccount = JSON.parse(serviceAccountKeyString);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

const db = admin.firestore();
const app = express();
app.use(express.json());

app.post('/validate-key', async (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) {
    return res.status(400).json({ status: 'error', message: 'Key and HWID are required.' });
  }

  try {
    const keysSnapshot = await db.collectionGroup('keys')
      .where('key_id', '==', key)
      .limit(1)
      .get();

    if (keysSnapshot.empty) {
      return res.status(404).json({ status: 'error', message: 'Key not found.' });
    }

    const keyDoc = keysSnapshot.docs[0];
    const keyData = keyDoc.data();

    if (keyData.status !== 'active' || (keyData.expires_at && keyData.expires_at.toDate() < new Date())) {
      return res.status(403).json({ status: 'error', message: 'Key is inactive or expired.' });
    }

    if (keyData.hwid && keyData.hwid !== hwid) {
      return res.status(403).json({ status: 'error', message: 'HWID mismatch.' });
    }

    if (!keyData.hwid) {
      await keyDoc.ref.update({ hwid: hwid });
      return res.status(200).json({ status: 'success', message: 'HWID assigned and key validated.' });
    }

    return res.status(200).json({ status: 'success', message: 'Key validated.' });

  } catch (error) {
    console.error('Validation error:', error);
    return res.status(500).json({ status: 'error', message: 'Internal server error.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});