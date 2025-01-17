require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid'); // Pour générer un identifiant unique

const stateValues = new Map(); // Stockage temporaire pour les states
const stateTimeouts = new Map();
const userDataStore = new Map(); // Stockage temporaire des données utilisateur

const app = express();
app.use(
  cors({
    origin: [
      'http://localhost:5173', // Frontend local
      'https://generate-cv-seven.vercel.app', // Frontend déployé
    ],
    methods: ['GET', 'POST'], // Autorise les méthodes nécessaires
    credentials: true, // Si vous utilisez des cookies ou des sessions
  })
);

app.use(bodyParser.json());

// Configuration des variables d'environnement
const CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || 'http://localhost:5000/api/linkedin/callback';
const BASE_URL = process.env.BASE_URL || 'http://localhost:5000';

// Endpoint pour importer des données LinkedIn
app.post('/api/linkedin/import', (req, res) => {
  const { linkedinUrl, templateId } = req.body;

  // Validation de l'URL LinkedIn
  if (!linkedinUrl || !linkedinUrl.startsWith('https://www.linkedin.com/in/')) {
    console.error('Invalid LinkedIn URL:', linkedinUrl);
    return res.status(400).json({ message: 'Veuillez fournir une URL LinkedIn valide.' });
  }

  console.log(`Import request received with templateId: ${templateId} and linkedinUrl: ${linkedinUrl}`);

  try {
    const authorizationUrl = `${BASE_URL}/api/linkedin/auth?templateId=${encodeURIComponent(templateId)}`;
    res.json({ authorizationUrl });
  } catch (error) {
    console.error('Error generating LinkedIn authorization URL:', error);
    res.status(500).json({ message: 'Erreur interne du serveur' });
  }
});

// Générer l'URL d'autorisation LinkedIn
app.get('/api/linkedin/auth', (req, res) => {
  const { templateId } = req.query;

  if (!templateId) {
    console.error('Template ID is missing in /api/linkedin/auth');
    return res.status(400).json({ error: 'Template ID is required.' });
  }

  console.log(`Received templateId: ${templateId}`);
  const state = crypto.randomBytes(16).toString('hex');
  stateValues.set(state, { templateId }); // Stocker le templateId associé au state
  console.log(`Generated state: ${state} for templateId: ${templateId}`);

  // Supprimer le state après 5 minutes
  const timeout = setTimeout(() => {
    stateValues.delete(state);
    stateTimeouts.delete(state);
  }, 5 * 60 * 1000); // 5 minutes

  stateTimeouts.set(state, timeout);

  const scope = 'openid profile email w_member_social';

  const authorizationUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&state=${state}&scope=${encodeURIComponent(scope)}`;

  res.redirect(authorizationUrl);
});

// Échanger le code d'autorisation contre un jeton d'accès
app.get('/api/linkedin/callback', async (req, res) => {
  const { code, state } = req.query;

  console.log(`Received code: ${code} and state: ${state}`);

  // Vérifier le state pour éviter une attaque CSRF
  if (!state || !stateValues.has(state)) {
    console.error('Invalid or missing state in /api/linkedin/callback');
    return res.status(400).json({ error: 'Invalid state. Potential CSRF attack detected.' });
  }

  const { templateId } = stateValues.get(state);
  stateValues.delete(state); // Supprimer le state après utilisation
  console.log(`State validated: ${state}. Associated templateId: ${templateId}`);

  if (!templateId) {
    console.error('Template ID is undefined after state validation');
    return res.status(500).json({ error: 'Template ID is undefined.' });
  }

  try {
    // Échanger le code d'autorisation contre un token d'accès
    const tokenResponse = await axios.post(
      'https://www.linkedin.com/oauth/v2/accessToken',
      null,
      {
        params: {
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
        },
      }
    );

    const accessToken = tokenResponse.data.access_token;
    console.log('Access token retrieved successfully.');

    // Obtenir les informations utilisateur (profil et email combinés)
    const profileResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    console.log('LinkedIn profile response:', profileResponse.data);

    // Extraire les données utilisateur
    const userData = {
      id: templateId,
      fullName: profileResponse.data.name, // Nom complet
      firstName: profileResponse.data.given_name, // Prénom
      lastName: profileResponse.data.family_name, // Nom
      profilePicture: profileResponse.data.picture, // URL de la photo de profil
      email: profileResponse.data.email || null, // Email (si disponible)
      emailVerified: profileResponse.data.email_verified || false, // Vérification email
    };

    console.log('Generated userData:', userData);

    // Stocker temporairement les données avec un identifiant unique
    const sessionId = uuidv4();
    console.log(`Generated sessionId: ${sessionId}`);
    userDataStore.set(sessionId, userData);

    // Rediriger vers le frontend avec l'ID du template et l'identifiant de session
    res.redirect(`http://localhost:5173/details/${templateId}?sessionId=${sessionId}`);
  } catch (error) {
    console.error('Error fetching LinkedIn data:', error.response?.data || error.message);
    res.status(500).send('Failed to fetch LinkedIn data');
  }
});

// Endpoint pour récupérer les données utilisateur via sessionId
app.get('/api/user-data/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  console.log(`Request received for sessionId: ${sessionId}`);
  
  if (userDataStore.has(sessionId)) {
    const userData = userDataStore.get(sessionId);
    // Garder les données utilisateur pour débogage ou tests
    console.log('User data retrieved:', userData);
    res.json(userData);
  } else {
    console.error(`Session ID not found: ${sessionId}`);
    res.status(404).json({ error: 'Session data not found' });
  }
});

// Lancer le serveur
 const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 

 module.exports = app; // Exporter l'application pour Vercel